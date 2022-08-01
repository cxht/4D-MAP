package quic

import (
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type streamFramer struct {
	streamsMap *streamsMap

	flowControlManager flowcontrol.FlowControlManager

	retransmissionQueue  []*wire.StreamFrame
	blockedFrameQueue    []*wire.BlockedFrame
	addAddressFrameQueue []*wire.AddAddressFrame
	closePathFrameQueue  []*wire.ClosePathFrame
	pathsFrame           *wire.PathsFrame

	retransbytes protocol.ByteCount
}

func newStreamFramer(streamsMap *streamsMap, flowControlManager flowcontrol.FlowControlManager) *streamFramer {
	return &streamFramer{
		streamsMap:         streamsMap,
		flowControlManager: flowControlManager,
	}
}

func (f *streamFramer) AddFrameForRetransmission(frame *wire.StreamFrame) {
	f.retransmissionQueue = append(f.retransmissionQueue, frame)
	f.retransbytes += frame.DataLen()
}
func (f *streamFramer) PopStreamFramesSTMS(maxLen protocol.ByteCount, sess *session, gap int, path_id protocol.PathID) []*wire.StreamFrame {
	fs, currentLen := f.maybePopFramesForRetransmission(maxLen)
	return append(fs, f.maybePopNormalFramesSTMS(maxLen-currentLen, sess, gap, path_id)...)
}

func (f *streamFramer) PopStreamFrames(maxLen protocol.ByteCount, sess *session) []*wire.StreamFrame {
	fs, currentLen := f.maybePopFramesForRetransmission(maxLen)
	return append(fs, f.maybePopNormalFrames(maxLen-currentLen, sess)...)
}
// func (f *streamFramer) PopStreamFramesWOFC(maxLen protocol.ByteCount) []*wire.StreamFrame {
// 	fs, currentLen := f.maybePopFramesForRetransmissionWOFC(maxLen)
// 	return append(fs, f.maybePopNormalFramesWOFC(maxLen-currentLen)...)
// }

// cx add 1228
// func (f *streamFramer) PopStream(maxLen protocol.ByteCount) []*wire.StreamFrame {
// 	fs, currentLen := f.maybePopFramesForRetransmissionWOFC(maxLen)
// 	return append(fs, f.maybePopNormalFramesWOFC(maxLen-currentLen)...)
// }

func (f *streamFramer) PopBlockedFrame() *wire.BlockedFrame {
	if len(f.blockedFrameQueue) == 0 {
		return nil
	}
	frame := f.blockedFrameQueue[0]
	f.blockedFrameQueue = f.blockedFrameQueue[1:]
	return frame
}

func (f *streamFramer) AddAddressForTransmission(ipVersion uint8, addr net.UDPAddr) {
	f.addAddressFrameQueue = append(f.addAddressFrameQueue, &wire.AddAddressFrame{IPVersion: ipVersion, Addr: addr})
}

func (f *streamFramer) PopAddAddressFrame() *wire.AddAddressFrame {
	if len(f.addAddressFrameQueue) == 0 {
		return nil
	}
	frame := f.addAddressFrameQueue[0]
	f.addAddressFrameQueue = f.addAddressFrameQueue[1:]
	return frame
}

func (f *streamFramer) AddPathsFrameForTransmission(s *session) {
	s.pathsLock.RLock()
	defer s.pathsLock.RUnlock()
	paths := make([]protocol.PathID, len(s.paths))
	remoteRTTs := make([]time.Duration, len(s.paths))
	i := 0
	for pathID := range s.paths {
		paths[i] = pathID
		if s.paths[pathID].potentiallyFailed.Get() {
			remoteRTTs[i] = time.Hour
		} else {
			remoteRTTs[i] = s.paths[pathID].rttStats.SmoothedRTT()
		}
		i++
	}
	f.pathsFrame = &wire.PathsFrame{MaxNumPaths: 255, NumPaths: uint8(len(paths)), PathIDs: paths, RemoteRTTs: remoteRTTs}
}

func (f *streamFramer) PopPathsFrame() *wire.PathsFrame {
	if f.pathsFrame == nil {
		return nil
	}
	frame := f.pathsFrame
	f.pathsFrame = nil
	return frame
}

func (f *streamFramer) AddClosePathFrameForTransmission(closePathFrame *wire.ClosePathFrame) {
	f.closePathFrameQueue = append(f.closePathFrameQueue, closePathFrame)
}

func (f *streamFramer) PopClosePathFrame() *wire.ClosePathFrame {
	if len(f.closePathFrameQueue) == 0 {
		return nil
	}
	frame := f.closePathFrameQueue[0]
	f.closePathFrameQueue = f.closePathFrameQueue[1:]
	return frame
}

func (f *streamFramer) HasFramesForRetransmission() bool {
	return len(f.retransmissionQueue) > 0
}

func (f *streamFramer) HasCryptoStreamFrame() bool {
	// TODO(#657): Flow control
	cs, _ := f.streamsMap.GetOrOpenStream(1)
	return cs.lenOfDataForWriting() > 0
}

// TODO(lclemente): This is somewhat duplicate with the normal path for generating frames.
// TODO(#657): Flow control
func (f *streamFramer) PopCryptoStreamFrame(maxLen protocol.ByteCount) *wire.StreamFrame {
	if !f.HasCryptoStreamFrame() {
		return nil
	}
	cs, _ := f.streamsMap.GetOrOpenStream(1)
	frame := &wire.StreamFrame{
		StreamID: 1,
		Offset:   cs.writeOffset,
	}
	frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
	frame.Data = cs.getDataForWriting(maxLen - frameHeaderBytes)
	return frame
}

// func (f *streamFramer) maybePopFramesForRetransmissionWOFC(maxLen protocol.ByteCount) (res []*wire.StreamFrame, currentLen protocol.ByteCount) {
// 	for len(f.retransmissionQueue) > 0 {
// 		frame := f.retransmissionQueue[0]
// 		frame.DataLenPresent = true

// 		frameHeaderLen, _ := frame.MinLength(protocol.VersionWhatever) // can never error
// 		if currentLen+frameHeaderLen >= maxLen {
// 			break
// 		}

// 		currentLen += frameHeaderLen

// 		splitFrame := maybeSplitOffFrame(frame, maxLen-currentLen)
// 		if splitFrame != nil { // StreamFrame was split
// 			res = append(res, splitFrame)
// 			frameLen := splitFrame.DataLen()
// 			currentLen += frameLen
// 			// XXX (QDC): to avoid rewriting a lot of tests...
// 			// if f.flowControlManager != nil {
// 			// 	f.flowControlManager.AddBytesRetrans(splitFrame.StreamID, frameLen)
// 			// }
// 			break
// 		}

// 		f.retransmissionQueue = f.retransmissionQueue[1:]
// 		res = append(res, frame)
// 		frameLen := frame.DataLen()
// 		currentLen += frameLen
// 		// XXX (QDC): to avoid rewriting a lot of tests...
// 		// if f.flowControlManager != nil {
// 		// 	f.flowControlManager.AddBytesRetrans(frame.StreamID, frameLen)
// 		// }
// 	}
// 	return
// }

func (f *streamFramer) maybePopFramesForRetransmission(maxLen protocol.ByteCount) (res []*wire.StreamFrame, currentLen protocol.ByteCount) {
	for len(f.retransmissionQueue) > 0 {
		frame := f.retransmissionQueue[0]
		frame.DataLenPresent = true

		frameHeaderLen, _ := frame.MinLength(protocol.VersionWhatever) // can never error
		if currentLen+frameHeaderLen >= maxLen {
			break
		}

		currentLen += frameHeaderLen

		splitFrame := maybeSplitOffFrame(frame, maxLen-currentLen)
		if splitFrame != nil { // StreamFrame was split
			res = append(res, splitFrame)
			frameLen := splitFrame.DataLen()
			currentLen += frameLen
			// XXX (QDC): to avoid rewriting a lot of tests...
			if f.flowControlManager != nil {
				f.flowControlManager.AddBytesRetrans(splitFrame.StreamID, frameLen)
			}
			break
		}

		f.retransmissionQueue = f.retransmissionQueue[1:]
		res = append(res, frame)
		frameLen := frame.DataLen()
		currentLen += frameLen
		// XXX (QDC): to avoid rewriting a lot of tests...
		if f.flowControlManager != nil {
			f.flowControlManager.AddBytesRetrans(frame.StreamID, frameLen)
		}
	}
	return
}


//cx add 1216
// func (f *streamFramer) PopGap(maxBytes protocol.ByteCount, maxFrameSize protocol.ByteCount) (res []*wire.StreamFrame) {
// 	if(maxBytes < maxFrameSize){
// 		fs := f.PopStreamFramesWOFC(maxBytes)
// 		res = append(res, fs...)
// 		utils.Infof("[strfr] pop dataforwriting  %v into sub_buffer",fs)
// 	}else{
// 		count:= maxBytes / maxFrameSize	
// 		utils.Infof("[strfr]  maxframesize limit %v",maxFrameSize)
// 		for i:=0 ; protocol.ByteCount(i) < count ;i++{
// 			fs := f.PopStreamFramesWOFC(maxFrameSize)
// 			res = append(res,fs...)
// 			//utils.Infof("[streamframer] pop dataforwriting into sub_buffer %v",fs)
// 		}
// 		utils.Infof("[strfr] pop %v frames into sub_buffer,  ",len(res))
// 	}
	
// 	return res
// }

//cx add 1228:  from popgap() to popgapbuffer(), from getdataforwriting and framing to getdataforwriting for bytes
// func (f *streamFramer) PopGapBuffer(maxBytes protocol.ByteCount, pth *path) () {
// 	//res = append(res, f.maybePopData(maxBytes, pth)...)
// 	//utils.Infof("[strfr] pop %v bytes into sub_buffer,  ",len(res))
// 	//f.maybePopData(maxBytes,pth)
// 	//return res
// }


// cx add 1228
func (f *streamFramer) maybePopData(maxBytes protocol.ByteCount, pth *path, redundancy protocol.ByteCount, sch *scheduler) () {
	var currentLen protocol.ByteCount
	fn := func(s *stream) (bool, error) {
		
		var now *utils.ByteIntervalElement
		// if s == nil || s.streamID == 1 /* crypto stream is handled separately */ {
		// 	return true, nil
		// }
		assigned_queue := pth.assigned_stream_off[s.streamID]
		if assigned_queue == nil {
			//utils.Infof("path %v, stream %v", pth.pathID, s.streamID)
			return true, nil
		}
		for now = assigned_queue.Front(); (now.Value.End - now.Value.Start) == 0; now = now.Next() {
			if  (now.Value.End - now.Value.Start) != 0 {
				break
			}
			if (now.Next() == nil){
				return true, nil
			}
		}
		
		if s == nil || s.streamID == 1 /* crypto stream is handled separately */ {
			return true, nil
		}

		if currentLen > maxBytes {
			return false, nil // theoretically, we could find another stream that fits, but this is quite unlikely, so we stop here
		}
		lenStreamData := s.lenOfDataForWriting()
		//utils.Infof("[sf]		Stream %v dataforwriting len: %v ", s.streamID, lenStreamData)
		if maxBytes == 0 {
			return true, nil
		}

		var data []byte
		if lenStreamData != 0 {
			// Only getDataForWriting() if we didn't have data earlier, so that we
			// don't send without FC approval (if a Write() raced).
			//make redundancy


			if(now.Value.Start != s.writeOffset){
				//utils.Infof("[sf]		Error: start_off 0x%x != writeoff 0x%x", now.Value.Start, s.writeOffset)
			}
			data = s.getDataForWriting(now.Value.End - now.Value.Start)
			//utils.Infof("[sf]		data len%v, start: %v, end: %v",len(data), now.Value.Start, now.Value.End )
			if pth.assigned_stream_off[s.streamID].Len() == 1{
				now.Value.Start = now.Value.End
				//utils.Infof("[sf]		assigned_streamoff updated now: %v, front: %v", now, pth.assigned_stream_off[s.streamID].Front())
			}else{
				now.Value.Start = now.Value.End
				//utils.Infof("[sf]		assigned_streamoff front: %v back: %v cnt %v", pth.assigned_stream_off[s.streamID].Front(), pth.assigned_stream_off[s.streamID].Back(), pth.assigned_stream_off[s.streamID].Len())
				pth.assigned_stream_off[s.streamID].Remove(pth.assigned_stream_off[s.streamID].Front())		
				//utils.Infof("[sf]		assigned_streamoff remove one: %v ", pth.assigned_stream_off[s.streamID].Front())
			}


			//////////////////////////////////////////////////
			if(pth.sess.config.IPriority){
			//utils.Infof("[sf]		BEFORE start:%v, end:%v, redundancy:%v",s.I_startinx, s.I_endinx, redundancy)
			if s.I_startinx >= -2 && s.I_startinx < len(data){
					if s.I_endinx == -1{
						redundancy = protocol.ByteCount(len(data))
						s.I_startinx = -2
					}else if s.I_endinx < len(data){
						redundancy = protocol.ByteCount(s.I_endinx)
						if s.I_endinx == -2{
							// s.I_startinx = 0
							// s.I_endinx = len(s.dataForWriting)		2022.3.2 find this line logic error
							s.I_startinx = -1
							s.I_endinx = -1
							s.hasI = false
							utils.Infof("[sf]		inx clear -1 -1")
						}else{
							s.I_startinx = -1
							s.I_endinx = -1
							s.hasI = false
							utils.Infof("[sf]		inx clear -1 -1")
						}
					}else if s.I_endinx >=  len(data){
						redundancy = protocol.ByteCount(len(data))
						s.I_endinx -=  len(data)
					}
			}else if s.I_startinx >= len(data) {
					redundancy = protocol.ByteCount(0)
					if s.I_endinx == -1{
						s.I_startinx -=  len(data)
					}else if s.I_endinx == -2{	// this condition can not happen
						//s.I_endinx = len(s.dataForWriting) 2022.3.2 find this line logic error
						utils.Infof("[sf]		[x, -2] this condition cannot happen")
						s.I_endinx = -1
					}else{
						s.I_endinx -=  len(data)
					}
			}
		
			//utils.Infof("[sf]		AFTER start:%v, end:%v, redundancy:%v",s.I_startinx, s.I_endinx, redundancy)
		}
			///////////////////////////////////
			if(redundancy > protocol.ByteCount(len(data))){
				redundancy = protocol.ByteCount(len(data))
			}	
			sch.redundancy_data = data[len(data) - int(redundancy): ]	
			sch.redundancy_stream_off_start = s.writeOffset - protocol.ByteCount(redundancy)
			sch.redundancy_stream_off_end = s.writeOffset
			//data = s.getDataForWriting(maxBytes)
			//utils.Infof("[sf]		lendata:%v red:%v ",len(data),redundancy)
			// if(pth.sub_buffer[s.streamID] == nil){
			// 	var group []byte
			// 	pth.sub_buffer[s.streamID] = group
			// }
			pth.data_insubbuffer += protocol.ByteCount(len(data))
			pth.sub_buffer[s.streamID] = append(pth.sub_buffer[s.streamID], data...)
			if(pth.stream_off[s.streamID] == nil){
				pth.stream_off[s.streamID] = utils.NewByteIntervalList()
				pth.stream_off[s.streamID].PushFront(utils.ByteInterval{Start:  s.writeOffset - protocol.ByteCount(len(data)), End:  s.writeOffset})
				//utils.Infof("[sf]length:%v %v",  pth.stream_off[s.streamID].Len(), pth.stream_off[s.streamID].Front())
			
				//pth.stream_off[s.streamID].PushBack(newoff)
				//utils.Infof("[sf]		from nil stream_off updated %v ", pth.stream_off[s.streamID].Front().Value)
			}else{
				//last_off := pth.stream_off[s.streamID][len(pth.stream_off) - 1]
				//utils.Infof("[sf]		end %v off %v data %v",pth.stream_off[s.streamID].Back().Value.End, s.writeOffset,len(data))
				last_off := pth.stream_off[s.streamID].Back()
				if last_off.Value.End == s.writeOffset - protocol.ByteCount(len(data)){				// same, just expand last_off
					pth.stream_off[s.streamID].Back().Value.End += protocol.ByteCount(len(data))
					//utils.Infof("[sf]		stream_off updated, cnt:%v, front:%v", pth.stream_off[s.streamID].Len(), pth.stream_off[s.streamID].Front())
				}else if last_off.Value.End < s.writeOffset - protocol.ByteCount(len(data) ){
					newoff := utils.ByteInterval{Start: s.writeOffset - protocol.ByteCount(len(data)), End:  s.writeOffset}
					pth.stream_off[s.streamID].PushBack(newoff)	
					//pth.stream_off[s.streamID] = append(pth.stream_off[s.streamID], newoff)
					//utils.Infof("[sf]		 stream_off updated, cnt:%v, front:%v ",pth.stream_off[s.streamID].Len(), pth.stream_off[s.streamID].Front())
				}else{
					//utils.Infof("[sf]		error!")
				}
			}
			
			//utils.Infof("[sf]		get bytes: %v from dataforwriting into sub_buffer of path %v :%v ",len(data), pth.pathID)

		}

		// This is unlikely, but check it nonetheless, the scheduler might have jumped in. Seems to happen in ~20% of cases in the tests.
		shouldSendFin := s.shouldSendFin()
		if data == nil && !shouldSendFin {
			//return true, nil
			return false, nil
		}

		if shouldSendFin {
			//frame.FinBit = true
			pth.fininx[s.streamID] = s.writeOffset - protocol.ByteCount(len(data))
			s.sentFin()
		}

		// frame.Data = data
		// //f.flowControlManager.AddBytesSent(s.streamID, protocol.ByteCount(len(data)))

		// // Finally, check if we are now FC blocked and should queue a BLOCKED frame
		// if f.flowControlManager.RemainingConnectionWindowSize() == 0 {
		// 	// We are now connection-level FC blocked
		// 	f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.BlockedFrame{StreamID: 0})
		// } else if !frame.FinBit && sendWindowSize-frame.DataLen() == 0 {
		// 	// We are now stream-level FC blocked
		// 	f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.BlockedFrame{StreamID: s.StreamID()})
		// }

		// res = append(res, frame)
		//currentLen += frameHeaderBytes + frame.DataLen()
		//res = append(res, data...)
		currentLen += protocol.ByteCount(len(data))
		if currentLen == maxBytes {
			return false, nil
		}

		//frame = &wire.StreamFrame{DataLenPresent: true}
		return true, nil
	}

	f.streamsMap.RoundRobinIterate(fn)

	return
}



// func (f *streamFramer) maybePopNormalFramesWOFC(maxBytes protocol.ByteCount) (res []*wire.StreamFrame) {
// 	frame := &wire.StreamFrame{DataLenPresent: true}
// 	var currentLen protocol.ByteCount

// 	fn := func(s *stream) (bool, error) {
// 		if s == nil || s.streamID == 1 /* crypto stream is handled separately */ {
// 			return true, nil
// 		}

// 		frame.StreamID = s.streamID
// 		// not perfect, but thread-safe since writeOffset is only written when getting data
// 		frame.Offset = s.writeOffset
// 		frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
// 		if currentLen+frameHeaderBytes > maxBytes {
// 			return false, nil // theoretically, we could find another stream that fits, but this is quite unlikely, so we stop here
// 		}
// 		maxLen := maxBytes - currentLen - frameHeaderBytes

// 		var sendWindowSize protocol.ByteCount
// 		lenStreamData := s.lenOfDataForWriting()
		
// 		if lenStreamData != 0 {
// 			sendWindowSize, _ = f.flowControlManager.SendWindowSize(s.streamID)
// 			maxLen = utils.MinByteCount(maxLen, sendWindowSize)
// 			//utils.Infof("[sf]snwd:%v, maxlen:%v",sendWindowSize,maxLen)
// 		}
// 		//utils.Infof("[sf]len of dataforwriting:%v maxlen:%v",lenStreamData, maxLen)
// 		if maxLen == 0 {
// 			return true, nil
// 		}

// 		var data []byte
// 		if lenStreamData != 0 {
// 			// Only getDataForWriting() if we didn't have data earlier, so that we
// 			// don't send without FC approval (if a Write() raced).
// 			data = s.getDataForWriting(maxLen)
// 			//////////////////////////////////////////////////
// 			utils.Infof("[sf]BEFORE start:%v, end:%v, priority:%b",s.I_startinx, s.I_endinx, frame.Priority)
// 			if s.I_startinx == -1 && s.I_endinx == -1{
// 				frame.Priority = false
// 			}else if s.I_startinx >= -2 && s.I_startinx < int(maxLen){
// 				if s.I_endinx == -1{
// 					frame.Priority = true
// 					s.I_startinx = -2
// 				}else if s.I_endinx <  int(maxLen){
// 					frame.Priority = true
// 					if s.I_endinx == -2{
// 						//s.I_startinx = 0
// 						//s.I_endinx = len(s.dataForWriting)
// 						s.I_startinx = -1
// 						s.I_endinx = -1
// 						s.hasI = false
// 					}else{
// 						s.I_startinx = -1
// 						s.I_endinx = -1
// 						s.hasI = false
// 					}
// 				}else if s.I_endinx >=  int(maxLen){
// 					frame.Priority = true
// 					s.I_startinx = 0
// 					s.I_endinx -=  int(maxLen)
// 				}
// 			}else if s.I_startinx >=  int(maxLen) {
// 				frame.Priority = false
// 				if s.I_endinx == -1{
// 					s.I_startinx -=  int(maxLen)
// 				}else if s.I_endinx == -2{
// 					//s.I_endinx = len(s.dataForWriting)		cannot happene
// 					s.I_endinx = -1
// 					s.hasI = false
// 				}else{
// 					s.I_endinx -=  int(maxLen)
// 				}
// 			}
// 			utils.Infof("[sf]AFTER start:%v, end:%v, priority:%b",s.I_startinx, s.I_endinx, frame.Priority)
// 			///////////////////////////////////
// 		}

// 		// This is unlikely, but check it nonetheless, the scheduler might have jumped in. Seems to happen in ~20% of cases in the tests.
// 		shouldSendFin := s.shouldSendFin()
// 		if data == nil && !shouldSendFin {
// 			return true, nil
// 		}

// 		if shouldSendFin {
// 			frame.FinBit = true
// 			s.sentFin()
// 		}

// 		frame.Data = data
// 		//f.flowControlManager.AddBytesSent(s.streamID, protocol.ByteCount(len(data)))

// 		// Finally, check if we are now FC blocked and should queue a BLOCKED frame
// 		if f.flowControlManager.RemainingConnectionWindowSize() == 0 {
// 			// We are now connection-level FC blocked
// 			f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.BlockedFrame{StreamID: 0})
// 		} else if !frame.FinBit && sendWindowSize-frame.DataLen() == 0 {
// 			// We are now stream-level FC blocked
// 			f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.BlockedFrame{StreamID: s.StreamID()})
// 		}

// 		res = append(res, frame)
// 		currentLen += frameHeaderBytes + frame.DataLen()

// 		if currentLen == maxBytes {
// 			return false, nil
// 		}

// 		frame = &wire.StreamFrame{DataLenPresent: true}
// 		return true, nil
// 	}

// 	f.streamsMap.RoundRobinIterate(fn)

// 	return
// }

func (f *streamFramer) Discard(maxLen protocol.ByteCount, sess *session, s *stream)(retPattern []byte, retPatternCnt int){
	pattern_discard := []byte{'a','b','c','d'} 
	retPatternCnt = 0 
	headerlen := 12			// without 13 BIT(I, OR P), because header is 12 bit.
	utils.Infof("I_start:%v, I_end:%v,nextheaderoff:%v,FLAGUNENOUGH:%v, lackbw:%v",s.I_startinx, s.I_endinx, s.NextHeaderOff, sess.scheduler.Flag_bw_unenough,  sess.scheduler.monitor.lackbw)
	if(sess.config.IPriority && sess.scheduler.monitor.lackbw == true && s.NextHeaderOff[0] != -3){
		
		// is this frame will over a videoframe header
		if( s.I_startinx != -1  && s.I_startinx >= 0 && s.I_startinx < ( int(maxLen) ) ){
			// case 1. I now
			//retStartInx = startInx
			if(s.NextHeaderOff[0] < int(maxLen)){
				if(len(s.NextHeaderOff) > 1){
					s.NextHeaderOff = s.NextHeaderOff[1:]
				}else{
					s.NextHeaderOff[0] = -1
				}
			}
			s.cansendpattern = true
			
		}else if( s.NextHeaderOff[0] >= 0 ){
			// case 2.0 P && header 
			retPattern = pattern_discard

			if(s.I_startinx >= 0){
				// p && I header
				s.I_startinx = 0 
				lendiscard := len(s.dataForWriting[ :s.NextHeaderOff[0]])
				s.dataForWriting = s.dataForWriting[ s.NextHeaderOff[0] : ]
				
				if(len(s.NextHeaderOff) > 1){
					s.NextHeaderOff = s.NextHeaderOff[1:]
					for i:=0 ; i < len(s.NextHeaderOff) ; i++{
						s.NextHeaderOff[i] -= lendiscard
					}
				}else{
					s.NextHeaderOff[0] = -1
				}
				
			}else{
				// next header is not I header, discard after information, only send header
				tmp := make([]byte, len(s.NextHeaderOff) * headerlen)
				for i:=0 ; i < len(s.NextHeaderOff) ; i++ {
					copy(tmp[ i * headerlen : i*headerlen + headerlen ], s.dataForWriting[ s.NextHeaderOff[i] : s.NextHeaderOff[i] + headerlen])
				}
				s.dataForWriting = tmp
				retPatternCnt = len(s.NextHeaderOff)
				
				// clear header off
				s.NextHeaderOff  = make([]int,1)
				s.NextHeaderOff[0] = -1
			}
			if(sess.scheduler.Flag_bw_unenough == false){
				// from enough to unenough, add a pattern at the begining
				retPatternCnt += 1
			}
			//s.NextHeaderOff = -1					// half header is not usual, other header move ahead
			s.cansendpattern = false
			
		}else if( s.NextHeaderOff[0] == -1 ){
			// case 2.1 P && no header now
			if(sess.scheduler.Flag_bw_unenough == false || s.cansendpattern == true){
				// only send pattern when suddenly change into unenough, else, pattern hasbeen sent.
				retPattern = pattern_discard
				retPatternCnt = 1
			}
			s.dataForWriting = nil
			s.signalWrite()
			//retStartInx = startInx + len(s.dataForWriting[startinx:])
			s.cansendpattern = false
		}
	}else if(sess.config.IPriority && sess.scheduler.monitor.lackbw == false && sess.scheduler.Flag_bw_unenough == true){
		
		if( s.NextHeaderOff[0] >= 0){
			// case 2.0 P && header over max, still discard
			if(s.I_startinx >= 0){
				//s.I_startinx update, next header must be an I header
				s.I_startinx = 0 
			}
			lendiscard := len(s.dataForWriting[ :s.NextHeaderOff[0]])
			s.dataForWriting = s.dataForWriting[ s.NextHeaderOff[0] : ]
			if(len(s.NextHeaderOff) > 1){
				s.NextHeaderOff = s.NextHeaderOff[1:]
				for i:=0 ; i < len(s.NextHeaderOff) ;i++{
					s.NextHeaderOff[i] -= lendiscard
				}
			}else{
				s.NextHeaderOff[0] = -1
			}

		}else if( s.NextHeaderOff[0] == -1 ){
			// case 2.1 P && no header now,still discard
			//retStartInx = startInx + len(s.dataForWriting[startinx:])
			s.dataForWriting = nil
			s.signalWrite()
		}
		sess.scheduler.Flag_bw_unenough = 	false
	}
	if(sess.config.IPriority && sess.scheduler.monitor.lackbw == true && s.NextHeaderOff[0] != -3 && sess.scheduler.Flag_bw_unenough == false){
		// is this frame will over a videoframe header
		sess.scheduler.Flag_bw_unenough = true
	}
	
	return retPattern, retPatternCnt
}


func (f *streamFramer) maybePopNormalFramesSTMS(maxBytes protocol.ByteCount, sess *session,gap  int,path_id protocol.PathID) (res []*wire.StreamFrame) {
	frame := &wire.StreamFrame{DataLenPresent: true}
	var currentLen protocol.ByteCount
	fn := func(s *stream) (bool, error) {
		if s == nil || s.streamID == 1 /* crypto stream is handled separately */ {
		
			return true, nil
		}

		if(gap < 0){
			if(s.writeOffsetF == s.writeOffsetSS && s.writeOffsetSS < s.writeOffsetSN){
				// fast have no gap  to send ,so following slower paths
				frame.Offset = s.writeOffsetSN
			}else{
				frame.Offset = s.writeOffsetF
			}
		}else{
			if(s.writeOffsetSN > s.writeOffsetSS ){
				frame.Offset = s.writeOffsetSN
			}else{
				frame.Offset = s.writeOffsetF +  protocol.ByteCount(gap)
			}
		}
		//utils.Infof("[sf]	stms writeoffsetnow:%v", frame.Offset)
		frame.StreamID = s.streamID
		// not perfect, but thread-safe since writeOffset is only written when getting data

		frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
		if currentLen+frameHeaderBytes > maxBytes {
			return false, nil // theoretically, we could find another stream that fits, but this is quite unlikely, so we stop here
		}
		maxLen := maxBytes - currentLen - frameHeaderBytes

		var sendWindowSize protocol.ByteCount
		lenStreamData := s.lenOfDataForWriting()
		
		if lenStreamData != 0 {
			sendWindowSize, _ = f.flowControlManager.SendWindowSize(s.streamID)
			maxLen = utils.MinByteCount(maxLen, sendWindowSize)
			//utils.Infof("[sf]snwd:%v, maxlen:%v",sendWindowSize,maxLen)
		}
		//utils.Infof("[sf]len of dataforwriting:%v maxlen:%v",lenStreamData, maxLen)
		if maxLen == 0 {
			return true, nil
		}

		var data []byte
		if lenStreamData != 0 {
			// Only getDataForWriting() if we didn't have data earlier, so that we
			// don't send without FC approval (if a Write() raced).
			data = s.getDataForWritingSTMS(maxLen, gap, path_id)
		}

		

		// This is unlikely, but check it nonetheless, the scheduler might have jumped in. Seems to happen in ~20% of cases in the tests.
		shouldSendFin := s.shouldSendFin()
		if data == nil && !shouldSendFin {
			return true, nil
		}

		if shouldSendFin {
			frame.FinBit = true
			s.sentFin()
		}

		frame.Data = data
		f.flowControlManager.AddBytesSent(s.streamID, protocol.ByteCount(len(data)))

		// Finally, check if we are now FC blocked and should queue a BLOCKED frame
		if f.flowControlManager.RemainingConnectionWindowSize() == 0 {
			// We are now connection-level FC blocked
			f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.BlockedFrame{StreamID: 0})
		} else if !frame.FinBit && sendWindowSize-frame.DataLen() == 0 {
			// We are now stream-level FC blocked
			f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.BlockedFrame{StreamID: s.StreamID()})
		}

		res = append(res, frame)
		currentLen += frameHeaderBytes + frame.DataLen()

		if currentLen == maxBytes {
			return false, nil
		}

		frame = &wire.StreamFrame{DataLenPresent: true}
		return true, nil
	}

	f.streamsMap.RoundRobinIterate(fn)

	return
}
func (f *streamFramer) maybePopNormalFrames(maxBytes protocol.ByteCount, sess *session) (res []*wire.StreamFrame) {
	// for minRTT, RR, ECF, BLEST..
	frame := &wire.StreamFrame{DataLenPresent: true}
	var currentLen protocol.ByteCount

	fn := func(s *stream) (bool, error) {
		if s == nil || s.streamID == 1 /* crypto stream is handled separately */ {
			return true, nil
		}

		frame.StreamID = s.streamID
		// not perfect, but thread-safe since writeOffset is only written when getting data
		frame.Offset = s.writeOffset
		frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
		if currentLen+frameHeaderBytes > maxBytes {
			return false, nil // theoretically, we could find another stream that fits, but this is quite unlikely, so we stop here
		}
		maxLen := maxBytes - currentLen - frameHeaderBytes

		var sendWindowSize protocol.ByteCount
		lenStreamData := s.lenOfDataForWriting()
		
		if lenStreamData != 0 {
			sendWindowSize, _ = f.flowControlManager.SendWindowSize(s.streamID)
			maxLen = utils.MinByteCount(maxLen, sendWindowSize)
			//utils.Infof("[sf]snwd:%v, maxlen:%v",sendWindowSize,maxLen)
		}
		//utils.Infof("[sf]len of dataforwriting:%v maxlen:%v",lenStreamData, maxLen)
		if maxLen == 0 {
			return true, nil
		}

		var data []byte
		if lenStreamData != 0 {
			// Only getDataForWriting() if we didn't have data earlier, so that we
			// don't send without FC approval (if a Write() raced).

			///////////////////////////pro-discard VERSION 2021/////////////////////////////
		// 	if(sess.config.IPriority){
		// 		lowBW := true 
		// 		if(lowBW == true && s.hasI == true && s.Iframecount >= 2){
		// 			var discard_s, discard_e int
		// 			if(s.I_startinx > 0){
		// 				discard_s = 0
		// 				discard_e = s.I_startinx
		// 				utils.Infof("[sf]		!!pro-discard %v bytes!", discard_e - discard_s)
		// 				_ = s.getDataForWriting(protocol.ByteCount(discard_e - discard_s))
		// 				if(s.I_endinx != -1){
		// 					s.I_endinx -= s.I_startinx
		// 				}
		// 				s.I_startinx  = 0
		// 			}
		// 		}
		// }
			//////////////////////////DISCARD VERSION 2022////////////////////////////////
			//utils.Infof("[sf]dataforwriting before:%v", s.dataForWriting)
			pattern, patterncnt := f.Discard(maxLen, sess, s)
			headerlen := 12
			//utils.Infof("[sf]dataforwriting after:%v", s.dataForWriting)
			//utils.Infof("[sf]patterncnt:%v, LENDATAFORWRITING:%v", patterncnt, len(s.dataForWriting) )
			if(patterncnt == -1){
				data = append(  pattern, s.getDataForWriting(maxLen)...)
				s.writeOffset +=  protocol.ByteCount(len(pattern))
			}else if(patterncnt > 0){
				if( patterncnt > ( len(s.dataForWriting) / headerlen)  ){
					// from enough to unenough
					data = append(  pattern, s.getDataForWriting(maxLen)...)
					patterncnt -= 1
					s.writeOffset += protocol.ByteCount(len(pattern))
				}
				for i := 0 ; i < patterncnt ; i++ {
					data = append(  data, s.getDataForWriting(protocol.ByteCount(headerlen))...)              //!!!!!!!!!!!!!!!!!!!!!!!!!1
					data = append( data, pattern...)
					//utils.Infof("[sf]data:%v", data)
					s.writeOffset +=  protocol.ByteCount(len(pattern))
					maxLen -= protocol.ByteCount(headerlen)
				}
				//utils.Infof("[sf]Discard:%v", data)
			}else{
				data = s.getDataForWriting(protocol.ByteCount(maxLen))
			}
			////////////////////////////////////////////////////////////////////

			//utils.Infof("[sf]BEFORE start:%v, end:%v, priority:%b",s.I_startinx, s.I_endinx, frame.Priority)
			
			tmp := make([]int, len(s.NextHeaderOff))
			tmp[0] = -1
			j := 0
			for i:=0 ; i < len(s.NextHeaderOff) ;i++{
				if( s.NextHeaderOff[i] > ( int(maxLen) )){
					tmp[j] = s.NextHeaderOff[i] - int(maxLen)
					j += 1
				}
			}
			
			if(j == 0){
				s.NextHeaderOff = tmp[:1]
			}else{
				s.NextHeaderOff = tmp[:j]
			}
			
			// update I_startinx and I_endinx 
			if s.I_startinx == -1 && s.I_endinx == -1{
				frame.Priority = false
			}else if s.I_startinx >= -2 && s.I_startinx < int(maxLen){
				if s.I_endinx == -1{
					frame.Priority = true
					s.I_startinx = -2
				}else if s.I_endinx <  int(maxLen){
					frame.Priority = true
					if s.I_endinx == -2{
						//s.I_startinx = 0
						//s.I_endinx = len(s.dataForWriting)		//2022 3.2 this line logic error
						s.I_endinx = -1
						s.I_startinx = -1
						s.hasI = false
					}else{
						s.I_startinx = -1
						s.I_endinx = -1
						s.hasI = false
					}
				}else if s.I_endinx >=  int(maxLen){
					frame.Priority = true
					s.I_startinx = 0
					s.I_endinx -=  int(maxLen)
				}
			}else if s.I_startinx >=  int(maxLen) {
				frame.Priority = false
				if s.I_endinx == -1{
					s.I_startinx -=  int(maxLen)
				}else if s.I_endinx == -2{			// this condition cannot happen
					//s.I_endinx = len(s.dataForWriting) /2022 3.2 this line logic error
					s.I_endinx = -1
					s.I_startinx = -1
					s.hasI = false
				}else{
					s.I_endinx -=  int(maxLen)
				}
			}
			//utils.Infof("[sf]AFTER start:%v, end:%v, priority:%b",s.I_startinx, s.I_endinx, frame.Priority)
			///////////////////////////////////
			
		}

		// This is unlikely, but check it nonetheless, the scheduler might have jumped in. Seems to happen in ~20% of cases in the tests.
		shouldSendFin := s.shouldSendFin()
		if data == nil && !shouldSendFin {
			return true, nil
		}

		if shouldSendFin {
			frame.FinBit = true
			s.sentFin()
		}

		frame.Data = data
		//utils.Infof("frame:%v,DATALEN:%v",frame.Data,frame.DataLen(),frame.FinBit)
		f.flowControlManager.AddBytesSent(s.streamID, protocol.ByteCount(len(data)))

		// Finally, check if we are now FC blocked and should queue a BLOCKED frame
		if f.flowControlManager.RemainingConnectionWindowSize() == 0 {
			// We are now connection-level FC blocked
			f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.BlockedFrame{StreamID: 0})
		} else if !frame.FinBit && sendWindowSize-frame.DataLen() == 0 {
			// We are now stream-level FC blocked
			f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.BlockedFrame{StreamID: s.StreamID()})
		}

		res = append(res, frame)
		currentLen += frameHeaderBytes + frame.DataLen()

		if currentLen == maxBytes {
			return false, nil
		}

		frame = &wire.StreamFrame{DataLenPresent: true}
		return true, nil
	}

	f.streamsMap.RoundRobinIterate(fn)

	return
}

// maybeSplitOffFrame removes the first n bytes and returns them as a separate frame. If n >= len(frame), nil is returned and nothing is modified.
func maybeSplitOffFrame(frame *wire.StreamFrame, n protocol.ByteCount) *wire.StreamFrame {
	if n >= frame.DataLen() {
		return nil
	}

	defer func() {
		frame.Data = frame.Data[n:]
		frame.Offset += n
	}()

	return &wire.StreamFrame{
		FinBit:         false,
		StreamID:       frame.StreamID,
		Offset:         frame.Offset,
		Data:           frame.Data[:n],
		DataLenPresent: frame.DataLenPresent,
	}
}
