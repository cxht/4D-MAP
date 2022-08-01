package quic

import (
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

const (
	minPathTimer = 10 * time.Millisecond
	// XXX (QDC): To avoid idling...
	maxPathTimer = 1 * time.Second
)
type streamoffdata struct{
	off int 
	datalen int 
}
type path struct {
	pathID protocol.PathID
	conn   connection
	sess   *session

	rttStats *congestion.RTTStats

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler

	open      utils.AtomicBool
	closeChan chan *qerr.QuicError
	runClosed chan struct{}

	potentiallyFailed utils.AtomicBool

	sentPacket          chan struct{}

	// It is now the responsibility of the path to keep its packet number
	packetNumberGenerator *packetNumberGenerator

	lastRcvdPacketNumber protocol.PacketNumber
	// Used to calculate the next packet number from the truncated wire
	// representation, and sent back in public reset packets
	largestRcvdPacketNumber protocol.PacketNumber

	leastUnacked protocol.PacketNumber

	lastNetworkActivityTime time.Time

	timer           *utils.Timer

	sub_buffer_origin  []*wire.StreamFrame                  //cx add 1213 for storing gaps, i.e., sub-dataforwriting
	sub_buffer map[protocol.StreamID][]byte
	assigned_stream_off map[protocol.StreamID]*utils.ByteIntervalList	//assigned to each path for deriving data from dataforwriting_buffer
	stream_off map[protocol.StreamID]*utils.ByteIntervalList		//real data get from dataforwriting_buffer(get based on assigned_stream_off)
	fininx map[protocol.StreamID]protocol.ByteCount			//record the fin index of a stream 
	data_insubbuffer protocol.ByteCount 
	inx int 					// for redundancy, to index an appropriate location at sub_buffer 

	sendinx int64
}

// setup initializes values that are independent of the perspective
func (p *path) setup(oliaSenders map[protocol.PathID]*congestion.OliaSender) {
	p.rttStats = &congestion.RTTStats{}

	var cong congestion.SendAlgorithm

	if p.sess.version >= protocol.VersionMP && oliaSenders != nil && p.pathID != protocol.InitialPathID {
		cong = congestion.NewOliaSender(oliaSenders, p.rttStats, protocol.InitialCongestionWindow, protocol.DefaultMaxCongestionWindow)
		oliaSenders[p.pathID] = cong.(*congestion.OliaSender)
	}

	sentPacketHandler := ackhandler.NewSentPacketHandler(p.rttStats, cong, p.onRTO)

	now := time.Now()

	p.sentPacketHandler = sentPacketHandler
	p.receivedPacketHandler = ackhandler.NewReceivedPacketHandler(p.sess.version)

	p.packetNumberGenerator = newPacketNumberGenerator(protocol.SkipPacketAveragePeriodLength)

	p.closeChan = make(chan *qerr.QuicError, 1)
	p.runClosed = make(chan struct{}, 1)
	p.sentPacket = make(chan struct{}, 1)

	p.timer = utils.NewTimer()
	p.lastNetworkActivityTime = now

	p.open.Set(true)
	p.potentiallyFailed.Set(false)

	// Once the path is setup, run it
	p.sub_buffer = make(map[protocol.StreamID][]byte)
	p.stream_off = make(map[protocol.StreamID]*utils.ByteIntervalList)
	p.assigned_stream_off = make(map[protocol.StreamID]*utils.ByteIntervalList)
	p.fininx = make(map[protocol.StreamID]protocol.ByteCount)
	p.data_insubbuffer = protocol.ByteCount(0)
	go p.run()
}

func (p *path) close() error {
	p.open.Set(false)
	return nil
}

func (p *path) run() {
	// XXX (QDC): relay everything to the session, maybe not the most efficient
runLoop:
	for {
		// Close immediately if requested
		select {
		case <-p.closeChan:
			break runLoop
		default:
		}

		p.maybeResetTimer()

		select {
		case <-p.closeChan:
			break runLoop
		case <-p.timer.Chan():
			p.timer.SetRead()
			select {
			case p.sess.pathTimers <- p:
			// XXX (QDC): don't remain stuck here!
			case <-p.closeChan:
				break runLoop
			case <-p.sentPacket:
				// Don't remain stuck here!
			}
		case <-p.sentPacket:
			// Used to reset the path timer
		}
	}
	p.close()
	p.runClosed <- struct{}{}
}

func (p *path) SendingAllowed(flag bool) bool {
	return p.open.Get() && p.sentPacketHandler.SendingAllowed(flag)
}

func (p *path) GetStopWaitingFrame(force bool) *wire.StopWaitingFrame {
	return p.sentPacketHandler.GetStopWaitingFrame(force)
}

func (p *path) GetAckFrame() *wire.AckFrame {
	ack := p.receivedPacketHandler.GetAckFrame()

	if ack != nil {
		ack.PathID = p.pathID
	// 	for pathID, _ := range p.sess.paths {
	// 		if(pathID != protocol.InitialPathID && pathID != p.pathID){
	// 			var ok,ok1 bool
	// 			if _, ok = p.sess.feedback_gap[pathID]; !ok{
	// 				ack.Feedback = 0
	// 				utils.Infof("!ok1")
	// 				break
	// 			}
	// 			if _, ok1 = p.sess.feedback_gap[p.pathID]; !ok1{
	// 				ack.Feedback = 0
	// 				utils.Infof("!ok1")
	// 				break
	// 			}
				
	// 			ack.Feedback = p.sess.feedback_gap[p.pathID] - p.sess.feedback_gap[pathID]
	// 		}
	// 	}
	}

	return ack
}

func (p *path) GetClosePathFrame() *wire.ClosePathFrame {
	closePathFrame := p.receivedPacketHandler.GetClosePathFrame()
	if closePathFrame != nil {
		closePathFrame.PathID = p.pathID
	}

	return closePathFrame
}

func (p *path) maybeResetTimer() {
	deadline := p.lastNetworkActivityTime.Add(p.idleTimeout())

	if ackAlarm := p.receivedPacketHandler.GetAlarmTimeout(); !ackAlarm.IsZero() {
		deadline = ackAlarm
	}
	if lossTime := p.sentPacketHandler.GetAlarmTimeout(); !lossTime.IsZero() {
		deadline = utils.MinTime(deadline, lossTime)
	}

	deadline = utils.MinTime(utils.MaxTime(deadline, time.Now().Add(minPathTimer)), time.Now().Add(maxPathTimer))

	p.timer.Reset(deadline)
}

func (p *path) idleTimeout() time.Duration {
	// TODO (QDC): probably this should be refined at path level
	cryptoSetup := p.sess.cryptoSetup
	if cryptoSetup != nil {
		if p.open.Get() && (p.pathID != 0 || p.sess.handshakeComplete) {
			return p.sess.connectionParameters.GetIdleConnectionStateLifetime()
		}
		return p.sess.config.HandshakeTimeout
	}
	return time.Second
}

func (p *path) handlePacketImpl(pkt *receivedPacket) error {
	if !p.open.Get() {
		// Path is closed, ignore packet
		return nil
	}

	if !pkt.rcvTime.IsZero() {
		p.lastNetworkActivityTime = pkt.rcvTime
	}
	hdr := pkt.publicHeader
	data := pkt.data

	// We just received a new packet on that path, so it works
	p.potentiallyFailed.Set(false)

	// Calculate packet number
	hdr.PacketNumber = protocol.InferPacketNumber(
		hdr.PacketNumberLen,
		p.largestRcvdPacketNumber,
		hdr.PacketNumber,
	)

	packet, err := p.sess.unpacker.Unpack(hdr.Raw, hdr, data)
	// if utils.Debug() {
	// 	if err != nil {
	// 		utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x on path %x ", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, p.pathID)
	// 	} else {
	// 		utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x on path %x, %s rtt:%v", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, p.pathID, packet.encryptionLevel, p.rttStats.SmoothedRTT())
	// 	}
	// }

	// if the decryption failed, this might be a packet sent by an attacker
	// don't update the remote address
	if quicErr, ok := err.(*qerr.QuicError); ok && quicErr.ErrorCode == qerr.DecryptionFailure {
		return err
	}
	if p.sess.perspective == protocol.PerspectiveServer {
		// update the remote address, even if unpacking failed for any other reason than a decryption error
		p.conn.SetCurrentRemoteAddr(pkt.remoteAddr)
	}
	if err != nil {
		return err
	}

	p.lastRcvdPacketNumber = hdr.PacketNumber
	// Only do this after decrupting, so we are sure the packet is not attacker-controlled
	p.largestRcvdPacketNumber = utils.MaxPacketNumber(p.largestRcvdPacketNumber, hdr.PacketNumber)

	isRetransmittable := ackhandler.HasRetransmittableFrames(packet.frames)
	if err = p.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, isRetransmittable,len(pkt.data)); err != nil {
		return err
	}

	if err != nil {
		return err
	}

	return p.sess.handleFrames(packet.frames, p, pkt.rcvTime)
}

func (p *path) onRTO(lastSentTime time.Time) bool {
	// Was there any activity since last sent packet?
	if p.lastNetworkActivityTime.Before(lastSentTime) {
		p.potentiallyFailed.Set(true)
		p.sess.schedulePathsFrame()
		return true
	}
	return false
}

func (p *path) SetLeastUnacked(leastUnacked protocol.PacketNumber) {
	p.leastUnacked = leastUnacked
}
//cx add 1226
// func (p *path) Selecthighpriorityframe() (frame *wire.StreamFrame, inx int){
// 	for i:=0 ;i < len(p.sub_buffer) ; i++ {
// 		f := p.sub_buffer[i]
// 		if f.Priority == true{
			
// 			return f, i
// 		}
// 	}
// 	return p.sub_buffer[0] , 0
// }
//cx add 1214: storing gaps
func (p *path) PopFramesFromBuffer(maxBytes protocol.ByteCount) (res []*wire.StreamFrame, length protocol.ByteCount) {
	
	frame := &wire.StreamFrame{DataLenPresent: true}
	var currentLen protocol.ByteCount
	frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
	utils.Infof("[pack]path %v have existing subffuer :%v",p.pathID, uint32(len(p.sub_buffer)))
	for {
		if currentLen + frameHeaderBytes >= maxBytes || !p.SendingAllowed(false){			//cx fix 1221 : to fix if cwnd <0, pkt still sent....
		//if currentLen + frameHeaderBytes >= maxBytes{
			//return false, nil // theoretically, we could find another stream that fits, but this is quite unlikely, so we stop here
			utils.Infof("[path]get from sub_buffer will over max, or cwnd over return")
			return res, currentLen
		}
		//maxLen := maxBytes - currentLen - frameHeaderBytes

		//var sendWindowSize protocol.ByteCount
		lenStreamData := len(p.sub_buffer)
		if lenStreamData == 0 {
			//utils.Infof("[pack]path %v len subffuer empty",p.pathID)
			return res, currentLen
		}


		//var data []byte
		if lenStreamData != 0 {
			// Only getDataForWriting() if we didn't have data earlier, so that we
			// don't send without FC approval (if a Write() raced).
			
			
			frame_inx := 0
			// //////////////////////////////////////
			// if p.sess.config.IPriority{
			// 	frame, frame_inx = p.Selecthighpriorityframe()
			// }else{
			// 	frame = p.sub_buffer[0]
			// }
			// if lenStreamData != 0 {
			// 	sendWindowSize, _ = p.sess.flowControlManager.SendWindowSize(frame.StreamID)
			// 	maxBytes = utils.MinByteCount(maxBytes, sendWindowSize)
			// 	utils.Infof("[path]snd buffer %v, maxBYTES:%v, %v",sendWindowSize, maxBytes, currentLen + frame.DataLen())
			// }
			// ////////////////////////////////////////////////////
			
			if int(currentLen + frame.DataLen()) > int(maxBytes - 12) {
				utils.Infof("[path]get %v from sub_buffer will over max %v, return",currentLen + frame.DataLen(), int(maxBytes - 12))
				return res, currentLen
			}
			
			if frame_inx == 0{
				p.sub_buffer_origin = p.sub_buffer_origin[1:]			//sub_buffer - 1
			}else{
				//utils.Infof("[path]i prio before : %v", p.sub_buffer)
				tmp := p.sub_buffer_origin[:frame_inx]
				// utils.Infof("[path]i prio pre %v", tmp)
				// utils.Infof("[path]i prio frame %v",p.sub_buffer[frame_inx])
				// utils.Infof("[path]i prio behind %v", p.sub_buffer[frame_inx + 1: ])
				p.sub_buffer_origin = append(tmp, p.sub_buffer_origin[frame_inx + 1: ]...)
				
			}
			p.sess.flowControlManager.AddBytesSent(frame.StreamID, protocol.ByteCount(len(frame.Data)))
			if(p.inx > 0){
				p.inx -= 1
			}

		}
		// Finally, check if we are now FC blocked and should queue a BLOCKED frame

		res = append(res, frame)
		currentLen += frameHeaderBytes + frame.DataLen()
		utils.Infof("[path] get  %d from sub buffer",len(res))
	}
}


// //cx add 1222: generate red to other availiable paths
// func (p *path) ReadRedFromBuffer(maxBytes protocol.ByteCount) (res []*wire.StreamFrame, length protocol.ByteCount) {
	
// 	frame := &wire.StreamFrame{DataLenPresent: true}
// 	var currentLen protocol.ByteCount
// 	frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
// 	utils.Infof("[path-red]path %v have existing subffuer :%v",p.pathID, uint32(len(p.sub_buffer)))
	
// 	for {
// 		if currentLen + frameHeaderBytes >= maxBytes || p.inx >= len(p.sub_buffer){			//cx fix 1221 : to fix if cwnd <0, pkt still sent....
// 			//return false, nil // theoretically, we could find another stream that fits, but this is quite unlikely, so we stop here
// 			utils.Infof("[path-red]get from sub_buffer will over max, or inx overflow, inx :%v",p.inx)
// 			return res, currentLen
// 		}
// 		//maxLen := maxBytes - currentLen - frameHeaderBytes

// 		//var sendWindowSize protocol.ByteCount
// 		lenStreamData := len(p.sub_buffer)
// 		if lenStreamData == 0 {
// 			utils.Infof("[path-red]path %v len subffuer empty",p.pathID)
// 			return res, currentLen
// 		}

// 		if lenStreamData != 0 {
// 			// Only getDataForWriting() if we didn't have data earlier, so that we
// 			// don't send without FC approval (if a Write() raced).
			
// 			frame = p.sub_buffer[p.inx]
// 			utils.Infof("[path-red] :%v",len(p.sub_buffer))
// 			if currentLen + frame.DataLen() > (maxBytes ) {
// 				utils.Infof("[path-red]get from sub_buffer %v will over max %v, return",currentLen + frame.DataLen(), (maxBytes) )
// 				return res, currentLen
// 			}
// 			if(p.inx < len(p.sub_buffer)){
// 				p.inx += 1				//return to zero
// 			}
// 			// if p.inx == len(p.sub_buffer){
// 			//  	//p.sub_buffer = p.sub_buffer[len(p.sub_buffer) / 2:]				// only test !!!!!
// 			// 	//p.sub_buffer = p.sub_buffer[:]
// 			// 	//utils.Infof("[path-red]clear sub_buffer %v", len(p.sub_buffer))
// 			// 	p.inx = 0
// 			// }
			

// 			//utils.Infof("[path]sub_buffer len:%v",len(p.sub_buffer))
// 			//uils.Infof("[path]: get %v from subbuf length:%v",frame, len(p.sub_buffer))
// 		}
// 		// Finally, check if we are now FC blocked and should queue a BLOCKED frame

// 		res = append(res, frame)
// 		currentLen += frameHeaderBytes + frame.DataLen()
// 		utils.Infof("[path-red] get data from sub buffer %d, inx :%v",currentLen, p.inx)

// 	}
// }

//cx 14: frames to bytes
func (p *path) NewPopFramesFromBuffer(maxBytes protocol.ByteCount) (res []*wire.StreamFrame, length protocol.ByteCount) {
	frame := &wire.StreamFrame{DataLenPresent: true}
	var currentLen protocol.ByteCount
	
	frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
	maxLen := maxBytes - currentLen - frameHeaderBytes
	
	
		if currentLen + frameHeaderBytes >= maxBytes || !p.SendingAllowed(false){			//cx fix 1221 : to fix if cwnd <0, pkt still sent....
		//if currentLen + frameHeaderBytes >= maxBytes{
			//return false, nil // theoretically, we could find another stream that fits, but this is quite unlikely, so we stop here
			//utils.Infof("[pth]	get from sub_buffer will over max, or cwnd over return")
			return res, currentLen
		}
		//maxLen := maxBytes - currentLen - frameHeaderBytes
		numStreams := uint32(len(p.sess.streamsMap.streams))
		//mark_unempty := false
		for i := uint32(0); i < numStreams; i++ {
			streamID := p.sess.streamsMap.openStreams[i]
			var sendWindowSize protocol.ByteCount
			var getbytes []byte

			lenStreamData := len(p.sub_buffer[streamID])
			if lenStreamData == 0 {
				//utils.Infof("[pth][pack-prepare]	Path %v Stream %v len sub_buffer empty, now res:%v",p.pathID, streamID, len(res))
				//mark_unempty = true
				//return res, currentLen
				continue
			}
		
			if lenStreamData != 0 {
				// Only getDataForWriting() if we didn't have data earlier, so that we
				// don't send without FC approval (if a Write() raced).
				//frame_inx := 0
				//utils.Infof("[pth]	Path %v Stream %v have existing sub_buffer: %v bytes", p.pathID, streamID, uint32(len(p.sub_buffer[streamID])))
				f := p.sess.streamFramer
				sendWindowSize, _ = f.flowControlManager.SendWindowSize(streamID)			// cx todo:fix!!!!!!!!!!!!!!!!!!!!!!!1stream id
				maxLen = utils.MinByteCount(maxLen, sendWindowSize)
				var now *utils.ByteIntervalElement 
				for now = p.stream_off[streamID].Front(); (now.Value.End - now.Value.Start) == 0; now = now.Next() {
					if  (now.Value.End - now.Value.Start) != 0 {
						//utils.Infof("[pth]	Now stream_off: %v", now)
						break
					}
				}
				frame.Offset = protocol.ByteCount(now.Value.Start)
				frameHeaderBytes, _ = frame.MinLength(protocol.VersionWhatever) 
				maxLen = maxBytes - currentLen - frameHeaderBytes
				maxLen = utils.MinByteCount(maxLen, protocol.ByteCount( (now.Value.End - now.Value.Start)))
				//utils.Infof("[pth]	maxLen:%v ", maxLen)
				if maxLen == 0{
					return res, currentLen
				}

				if protocol.ByteCount(lenStreamData) > maxLen {
					getbytes = p.sub_buffer[streamID][:maxLen]
					p.sub_buffer[streamID] = p.sub_buffer[streamID][maxLen:]
				} else {
					getbytes = p.sub_buffer[streamID]
					p.sub_buffer[streamID] = nil
					
					//s.signalWrite()
				}
				p.data_insubbuffer -= protocol.ByteCount(len(getbytes))
				//utils.Infof("[pth]	stream_off: front %v, back %v, totallen:%v len getbytes:%v", p.stream_off[streamID].Front(), p.stream_off[streamID].Back(), p.stream_off[streamID].Len(), len(getbytes))
				
				if protocol.ByteCount(len(getbytes)) < ( (now.Value.End - now.Value.Start)){
					frame.Offset = protocol.ByteCount(now.Value.Start)
					now.Value.Start += protocol.ByteCount(len(getbytes))
					//p.stream_off[streamID].Front().End  -= len(getbytes)
					//utils.Infof("[pth]	stream_off not assumed completely front: %v", now)
				}else{
					//utils.Infof("[pth]%v ", p.stream_off[streamID])
					frame.Offset = now.Value.Start
					if p.stream_off[streamID].Len() == 1{
						now.Value.Start = now.Value.End
					}else{
						now.Value.Start = now.Value.End
						p.stream_off[streamID].Remove(p.stream_off[streamID].Front())		
					}			

					//utils.Infof("[pth]	stream_off assumed one front: %v, totallen:%v", p.stream_off[streamID].Front(),p.stream_off[streamID].Len())
				}
				if(p.fininx[streamID]!=0 && frame.Offset >= p.fininx[streamID]){
					frame.FinBit = true
				}
				p.sendinx = int64(frame.Offset)
				frame.StreamID = streamID
				//pack into frames
				frame.Data = getbytes
				
				frameHeaderBytes,_ =  frame.MinLength(protocol.VersionWhatever)
				res = append(res, frame)
				currentLen += frameHeaderBytes + frame.DataLen()
				maxLen = maxBytes - currentLen - frameHeaderBytes
				//utils.Infof("[pth]	get  data %d bytes from sub_buffer",len(res))
				//fc 
				f.flowControlManager.AddBytesSent(streamID, protocol.ByteCount(len(getbytes)))		// fix 
				sendWindowSize, _ = f.flowControlManager.SendWindowSize(streamID)
				//utils.Infof("[pth]	updated snwd: %v", sendWindowSize)
				// Finally, check if we are now FC blocked and should queue a BLOCKED frame
				if f.flowControlManager.RemainingConnectionWindowSize() == 0 {
					// We are now connection-level FC blocked
					f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.BlockedFrame{StreamID: 0})
				} else if !frame.FinBit && sendWindowSize-frame.DataLen() == 0 {
					// We are now stream-level FC blocked
					//f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.BlockedFrame{StreamID: s.StreamID()})
					f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.BlockedFrame{StreamID: protocol.StreamID(3)})
				}
			
			//////////////////////////////////////
			// if p.sess.config.IPriority{
			// 	frame, frame_inx = p.Selecthighpriorityframe()
			// }else{
			// 	frame = p.sub_buffer[0]
			// }
			// if lenStreamData != 0 {
			// 	sendWindowSize, _ = p.sess.flowControlManager.SendWindowSize(frame.StreamID)
			// 	maxBytes = utils.MinByteCount(maxBytes, sendWindowSize)
			// 	utils.Infof("[path]snd buffer %v, maxBYTES:%v, %v",sendWindowSize, maxBytes, currentLen + frame.DataLen())
			// }
			// if frame_inx == 0{
			// 	p.sub_buffer = p.sub_buffer[1:]			//sub_buffer - 1
			// }else{
			// 	//utils.Infof("[path]i prio before : %v", p.sub_buffer)
			// 	tmp := p.sub_buffer[:frame_inx]
			// 	// utils.Infof("[path]i prio pre %v", tmp)
			// 	// utils.Infof("[path]i prio frame %v",p.sub_buffer[frame_inx])
			// 	// utils.Infof("[path]i prio behind %v", p.sub_buffer[frame_inx + 1: ])
			// 	p.sub_buffer = append(tmp, p.sub_buffer[frame_inx + 1: ]...)
				
			// }
			////////////////////////////////////////////////////
			}
		}
		
		return res, currentLen

		// Finally, check if we are now FC blocked and should queue a BLOCKED frame

		
	
}
