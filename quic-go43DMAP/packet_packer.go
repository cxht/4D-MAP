package quic

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type packedPacket struct {
	number          protocol.PacketNumber
	raw             []byte
	frames          []wire.Frame
	encryptionLevel protocol.EncryptionLevel
}

type packetPacker struct {
	connectionID protocol.ConnectionID
	perspective  protocol.Perspective
	version      protocol.VersionNumber
	cryptoSetup  handshake.CryptoSetup

	connectionParameters  handshake.ConnectionParametersManager
	streamFramer          *streamFramer

	controlFrames []wire.Frame
	stopWaiting   map[protocol.PathID]*wire.StopWaitingFrame
	ackFrame      map[protocol.PathID]*wire.AckFrame
	firstpayloadFrames []wire.Frame // cx add 1219 for redundancy scheduler
	lastpayloadFrames []wire.Frame //for rtt==0 path
	lastdataforwritinglen protocol.ByteCount
}

func newPacketPacker(connectionID protocol.ConnectionID,
	cryptoSetup handshake.CryptoSetup,
	connectionParameters handshake.ConnectionParametersManager,
	streamFramer *streamFramer,
	perspective protocol.Perspective,
	version protocol.VersionNumber,
) *packetPacker {
	
	return &packetPacker{
		cryptoSetup:           cryptoSetup,
		connectionID:          connectionID,
		connectionParameters:  connectionParameters,
		perspective:           perspective,
		version:               version,
		streamFramer:          streamFramer,
		stopWaiting:           make(map[protocol.PathID]*wire.StopWaitingFrame),
		ackFrame:              make(map[protocol.PathID]*wire.AckFrame),
	}
}

// PackConnectionClose packs a packet that ONLY contains a ConnectionCloseFrame
func (p *packetPacker) PackConnectionClose(ccf *wire.ConnectionCloseFrame, pth *path) (*packedPacket, error) {
	frames := []wire.Frame{ccf}
	encLevel, sealer := p.cryptoSetup.GetSealer()
	ph := p.getPublicHeader(encLevel, pth)
	raw, err := p.writeAndSealPacket(ph, frames, sealer, pth)
	return &packedPacket{
		number:          ph.PacketNumber,
		raw:             raw,
		frames:          frames,
		encryptionLevel: encLevel,
	}, err
}

// PackPing packs a packet that ONLY contains a PingFrame
func (p *packetPacker) PackPing(pf *wire.PingFrame, pth *path) (*packedPacket, error) {
	// Add the PingFrame in front of the controlFrames
	pth.SetLeastUnacked(pth.sentPacketHandler.GetLeastUnacked())
	p.controlFrames = append([]wire.Frame{pf}, p.controlFrames...)
	return p.PackPacket(pth)
}

// PackPing packs a packet that ONLY contains a PingFrame
func (p *packetPacker) PackPingMOOO(pf *wire.PingFrame, pth *path) (*packedPacket, error) {
	// Add the PingFrame in front of the controlFrames
	pth.SetLeastUnacked(pth.sentPacketHandler.GetLeastUnacked())
	p.controlFrames = append([]wire.Frame{pf}, p.controlFrames...)
	return p.PackPacketMOOO(pth, nil)
}

func (p *packetPacker) PackAckPacket(pth *path) (*packedPacket, error) {
	if p.ackFrame[pth.pathID] == nil {
		return nil, errors.New("packet packer BUG: no ack frame queued")
	}
	encLevel, sealer := p.cryptoSetup.GetSealer()
	ph := p.getPublicHeader(encLevel, pth)
	frames := []wire.Frame{p.ackFrame[pth.pathID]}
	if p.stopWaiting[pth.pathID] != nil {
		p.stopWaiting[pth.pathID].PacketNumber = ph.PacketNumber
		p.stopWaiting[pth.pathID].PacketNumberLen = ph.PacketNumberLen
		frames = append(frames, p.stopWaiting[pth.pathID])
		p.stopWaiting[pth.pathID] = nil
	}
	p.ackFrame[pth.pathID] = nil
	raw, err := p.writeAndSealPacket(ph, frames, sealer, pth)
	return &packedPacket{
		number:          ph.PacketNumber,
		raw:             raw,
		frames:          frames,
		encryptionLevel: encLevel,
	}, err
}

// PackHandshakeRetransmission retransmits a handshake packet, that was sent with less than forward-secure encryption
func (p *packetPacker) PackHandshakeRetransmission(packet *ackhandler.Packet, pth *path) (*packedPacket, error) {
	if packet.EncryptionLevel == protocol.EncryptionForwardSecure {
		return nil, errors.New("PacketPacker BUG: forward-secure encrypted handshake packets don't need special treatment")
	}
	sealer, err := p.cryptoSetup.GetSealerWithEncryptionLevel(packet.EncryptionLevel)
	if err != nil {
		return nil, err
	}
	if p.stopWaiting[pth.pathID] == nil {
		return nil, errors.New("PacketPacker BUG: Handshake retransmissions must contain a StopWaitingFrame")
	}
	ph := p.getPublicHeader(packet.EncryptionLevel, pth)
	p.stopWaiting[pth.pathID].PacketNumber = ph.PacketNumber
	p.stopWaiting[pth.pathID].PacketNumberLen = ph.PacketNumberLen
	frames := append([]wire.Frame{p.stopWaiting[pth.pathID]}, packet.Frames...)
	p.stopWaiting[pth.pathID] = nil
	raw, err := p.writeAndSealPacket(ph, frames, sealer, pth)
	return &packedPacket{
		number:          ph.PacketNumber,
		raw:             raw,
		frames:          frames,
		encryptionLevel: packet.EncryptionLevel,
	}, err
}

// cx add 1214:
func (p *packetPacker) PackPacketRedundancy(pth *path, isfirst bool) (*packedPacket, error) {
	if p.streamFramer.HasCryptoStreamFrame() {
		return p.packCryptoPacket(pth)
	}

	encLevel, sealer := p.cryptoSetup.GetSealer()

	publicHeader := p.getPublicHeader(encLevel, pth)
	publicHeaderLength, err := publicHeader.GetLength(p.perspective)
	if err != nil {
		return nil, err
	}
	if p.stopWaiting[pth.pathID] != nil {
		p.stopWaiting[pth.pathID].PacketNumber = publicHeader.PacketNumber
		p.stopWaiting[pth.pathID].PacketNumberLen = publicHeader.PacketNumberLen
	}

	// TODO (QDC): rework this part with PING
	var isPing bool
	if len(p.controlFrames) > 0 {
		_, isPing = p.controlFrames[0].(*wire.PingFrame)
	}

	var payloadFrames []wire.Frame
	if isPing {
		payloadFrames = []wire.Frame{p.controlFrames[0]}
		// Remove the ping frame from the control frames
		p.controlFrames = p.controlFrames[1:len(p.controlFrames)]
	} else {
		maxSize := protocol.MaxPacketSize - protocol.ByteCount(sealer.Overhead()) - publicHeaderLength
		if isfirst{
			p.firstpayloadFrames = []wire.Frame{}
			payloadFrames, err = p.composeNextPacket(maxSize, p.canSendData(encLevel), pth)
			for _, frame := range payloadFrames {
				switch frame.(type) {
				case *wire.StreamFrame:
					p.firstpayloadFrames = append(p.firstpayloadFrames, frame)
				}
			}
			
			if err != nil {
				return nil, err
			}

			// if false{
			// 	// red_payload = 
			// 	// red_frame = 
			// 	// 1. compute alpha
			// 	if toobig{
			// 		// 2. make redundancy
			// 		alpha =  float64( -sch.monitor.state_serverinx[protocol.PathID(inx)] / 10.0)
			// 		red_frame = p.firstpayloadFrames[-1]
			// 		red_payload = p.firstpayloadFrames[-1] * alpha 
			// 	}else{
			// 		alpha = 0	
			// 	}
			// 	newoffset = red_frame.Offset + len(red_payload)
			// 	maxSize -= len(red_payload)
			// }
			utils.Infof("[pack]red-sch: first")
		}else{
			//payloadFrames, err = p.composeNextPacket(maxSize , false, pth)
			payloadFrames = append(payloadFrames, p.firstpayloadFrames...)			// add payloadframes
			utils.Infof("[pack]red-sch: other")
			for _, frame := range payloadFrames {
				wire.LogFrame(frame, true)
			}
		}

	}

	// Check if we have enough frames to send
	if len(payloadFrames) == 0 {
		return nil, nil
	}
	// Don't send out packets that only contain a StopWaitingFrame
	if len(payloadFrames) == 1 && p.stopWaiting[pth.pathID] != nil {
		return nil, nil
	}
	p.stopWaiting[pth.pathID] = nil
	p.ackFrame[pth.pathID] = nil
	raw, err := p.writeAndSealPacket(publicHeader, payloadFrames, sealer, pth)
	if err != nil {
		return nil, err
	}
	if raw == nil {				//cx add 1219
		return nil,nil
	}
	return &packedPacket{
		number:          publicHeader.PacketNumber,
		raw:             raw,
		frames:          payloadFrames,
		encryptionLevel: encLevel,
	}, nil
}
// cx add 1214:
func (p *packetPacker) PackPacketMOOO(pth *path, gap map[uint8] int) (*packedPacket, error) {
	if p.streamFramer.HasCryptoStreamFrame() {

		return p.packCryptoPacket(pth)
	}

	encLevel, sealer := p.cryptoSetup.GetSealer()

	publicHeader := p.getPublicHeader(encLevel, pth)
	publicHeaderLength, err := publicHeader.GetLength(p.perspective)
	if err != nil {
		return nil, err
	}
	if p.stopWaiting[pth.pathID] != nil {
		p.stopWaiting[pth.pathID].PacketNumber = publicHeader.PacketNumber
		p.stopWaiting[pth.pathID].PacketNumberLen = publicHeader.PacketNumberLen
	}

	// TODO (QDC): rework this part with PING
	var isPing bool
	if len(p.controlFrames) > 0 {
		_, isPing = p.controlFrames[0].(*wire.PingFrame)
	}

	var payloadFrames []wire.Frame
	if isPing {
		payloadFrames = []wire.Frame{p.controlFrames[0]}
		// Remove the ping frame from the control frames
		p.controlFrames = p.controlFrames[1:len(p.controlFrames)]
	} else {
		maxSize := protocol.MaxPacketSize - protocol.ByteCount(sealer.Overhead()) - publicHeaderLength
		payloadFrames, err = p.composeNextPacketMOOO(maxSize, p.canSendData(encLevel), pth, gap)
		p.lastpayloadFrames = payloadFrames
		if err != nil {
			return nil, err
		}
	}

	// Check if we have enough frames to send
	if len(payloadFrames) == 0 {
		return nil, nil
	}
	// Don't send out packets that only contain a StopWaitingFrame
	if len(payloadFrames) == 1 && p.stopWaiting[pth.pathID] != nil {
		return nil, nil
	}
	p.stopWaiting[pth.pathID] = nil
	p.ackFrame[pth.pathID] = nil
	raw, err := p.writeAndSealPacket(publicHeader, payloadFrames, sealer, pth)
	if err != nil {
		return nil, err
	}
	return &packedPacket{
		number:          publicHeader.PacketNumber,
		raw:             raw,
		frames:          payloadFrames,
		encryptionLevel: encLevel,
	}, nil
}

func (p *packetPacker) PackPacketSTMS(pth *path,gap  int) (*packedPacket, error) {
	if p.streamFramer.HasCryptoStreamFrame() {
		return p.packCryptoPacket(pth)
	}

	encLevel, sealer := p.cryptoSetup.GetSealer()

	publicHeader := p.getPublicHeader(encLevel, pth)
	publicHeaderLength, err := publicHeader.GetLength(p.perspective)
	if err != nil {
		return nil, err
	}
	if p.stopWaiting[pth.pathID] != nil {
		p.stopWaiting[pth.pathID].PacketNumber = publicHeader.PacketNumber
		p.stopWaiting[pth.pathID].PacketNumberLen = publicHeader.PacketNumberLen
	}

	// TODO (QDC): rework this part with PING
	var isPing bool
	if len(p.controlFrames) > 0 {
		_, isPing = p.controlFrames[0].(*wire.PingFrame)
	}

	var payloadFrames []wire.Frame
	if isPing {
		payloadFrames = []wire.Frame{p.controlFrames[0]}
		// Remove the ping frame from the control frames
		p.controlFrames = p.controlFrames[1:len(p.controlFrames)]
	} else {
		maxSize := protocol.MaxPacketSize - protocol.ByteCount(sealer.Overhead()) - publicHeaderLength
	
		payloadFrames, err = p.composeNextPacketSTMS(maxSize, p.canSendData(encLevel), pth, gap)
		if err != nil {
			return nil, err
		}
	}

	// Check if we have enough frames to send
	if len(payloadFrames) == 0 {
		return nil, nil
	}
	// Don't send out packets that only contain a StopWaitingFrame
	if len(payloadFrames) == 1 && p.stopWaiting[pth.pathID] != nil {
		return nil, nil
	}
	p.stopWaiting[pth.pathID] = nil
	p.ackFrame[pth.pathID] = nil

	raw, err := p.writeAndSealPacket(publicHeader, payloadFrames, sealer, pth)
	if err != nil {
		return nil, err
	}
	return &packedPacket{
		number:          publicHeader.PacketNumber,
		raw:             raw,
		frames:          payloadFrames,
		encryptionLevel: encLevel,
	}, nil
}
// PackPacket packs a new packet
// the other controlFrames are sent in the next packet, but might be queued and sent in the next packet if the packet would overflow MaxPacketSize otherwise
func (p *packetPacker) PackPacket(pth *path) (*packedPacket, error) {
	if p.streamFramer.HasCryptoStreamFrame() {
		return p.packCryptoPacket(pth)
	}

	encLevel, sealer := p.cryptoSetup.GetSealer()

	publicHeader := p.getPublicHeader(encLevel, pth)
	publicHeaderLength, err := publicHeader.GetLength(p.perspective)
	if err != nil {
		return nil, err
	}
	if p.stopWaiting[pth.pathID] != nil {
		p.stopWaiting[pth.pathID].PacketNumber = publicHeader.PacketNumber
		p.stopWaiting[pth.pathID].PacketNumberLen = publicHeader.PacketNumberLen
	}

	// TODO (QDC): rework this part with PING
	var isPing bool
	if len(p.controlFrames) > 0 {
		_, isPing = p.controlFrames[0].(*wire.PingFrame)
	}

	var payloadFrames []wire.Frame
	if isPing {
		payloadFrames = []wire.Frame{p.controlFrames[0]}
		// Remove the ping frame from the control frames
		p.controlFrames = p.controlFrames[1:len(p.controlFrames)]
	} else {
		maxSize := protocol.MaxPacketSize - protocol.ByteCount(sealer.Overhead()) - publicHeaderLength
	
		payloadFrames, err = p.composeNextPacket(maxSize, p.canSendData(encLevel), pth)
		if err != nil {
			return nil, err
		}
	}

	// Check if we have enough frames to send
	if len(payloadFrames) == 0 {
		return nil, nil
	}
	// Don't send out packets that only contain a StopWaitingFrame
	if len(payloadFrames) == 1 && p.stopWaiting[pth.pathID] != nil {
		return nil, nil
	}
	p.stopWaiting[pth.pathID] = nil
	p.ackFrame[pth.pathID] = nil

	raw, err := p.writeAndSealPacket(publicHeader, payloadFrames, sealer, pth)
	if err != nil {
		return nil, err
	}
	return &packedPacket{
		number:          publicHeader.PacketNumber,
		raw:             raw,
		frames:          payloadFrames,
		encryptionLevel: encLevel,
	}, nil
}

func (p *packetPacker) packCryptoPacket(pth *path) (*packedPacket, error) {
	encLevel, sealer := p.cryptoSetup.GetSealerForCryptoStream()
	publicHeader := p.getPublicHeader(encLevel, pth)
	publicHeaderLength, err := publicHeader.GetLength(p.perspective)
	if err != nil {
		return nil, err
	}
	maxLen := protocol.MaxPacketSize - protocol.ByteCount(sealer.Overhead()) - protocol.NonForwardSecurePacketSizeReduction - publicHeaderLength
	frames := []wire.Frame{p.streamFramer.PopCryptoStreamFrame(maxLen)}
	raw, err := p.writeAndSealPacket(publicHeader, frames, sealer, pth)
	if err != nil {
		return nil, err
	}
	return &packedPacket{
		number:          publicHeader.PacketNumber,
		raw:             raw,
		frames:          frames,
		encryptionLevel: encLevel,
	}, nil
}

//cx add 1214
func (p *packetPacker) composeNextPacketMOOO(
	maxFrameSize protocol.ByteCount,
	canSendStreamFrames bool,
	pth *path, gap map[uint8] int,
) ([]wire.Frame, error) {
	var payloadLength protocol.ByteCount
	var payloadFrames []wire.Frame

	// STOP_WAITING and ACK will always fit

	if p.stopWaiting[pth.pathID] != nil {
		payloadFrames = append(payloadFrames, p.stopWaiting[pth.pathID])
		l, err := p.stopWaiting[pth.pathID].MinLength(p.version)
		if err != nil {
			return nil, err
		}
		payloadLength += l
		//utils.Infof("[pack]sw:%v",payloadLength)
	}
	if p.ackFrame[pth.pathID] != nil {
		payloadFrames = append(payloadFrames, p.ackFrame[pth.pathID])
		l, err := p.ackFrame[pth.pathID].MinLength(p.version)
		//utils.Infof("[pack]ack:%v",payloadLength)
		if err != nil {
			return nil, err
		}
		payloadLength += l
	}

	// pack control frames
	//utils.Infof("[pack] len ctrl frame: %v", len(p.controlFrames))
	for len(p.controlFrames) > 0 {
		frame := p.controlFrames[len(p.controlFrames) - 1]
		minLength, err := frame.MinLength(p.version)
		//utils.Infof("[pack]minLenghth: %v",minLength)
		if err != nil {
			return nil, err
		}
		if payloadLength+minLength > maxFrameSize {
			break
		}
		payloadFrames = append(payloadFrames, frame)
		payloadLength += minLength
		p.controlFrames = p.controlFrames[:len(p.controlFrames)-1]
	}
	//utils.Infof("[pack]before pack payload: %v, maxsize %v", payloadLength, maxFrameSize)
	if payloadLength > maxFrameSize {
		return nil, fmt.Errorf("Packet Packer BUG: packet payload (%d) too large (%d)", payloadLength, maxFrameSize)
	}

	if !canSendStreamFrames {
		return payloadFrames, nil
	}

	// temporarily increase the maxFrameSize by 2 bytes
	// this leads to a properly sized packet in all cases, since we do all the packet length calculations with StreamFrames that have the DataLen set
	// however, for the last StreamFrame in the packet, we can omit the DataLen, thus saving 2 bytes and yielding a packet of exactly the correct size
	//maxFrameSize += 2
	//cx add 1214: first get data from buffer.
	//fs, currentLen := pth.PopFramesFromBuffer(maxFrameSize - payloadLength)	
	//cx add 14
	//1. split now dataforwrting into sub_buffers
	// gap_now := gap[uint8(pth.pathID)]
	// p.streamFramer.maybePopData(protocol.ByteCount(gap_now), pth)
	minus := protocol.ByteCount(0)
	utils.Infof("control frame len:%v", len(payloadFrames))
	if(len(payloadFrames) > 0){
		minus = protocol.ByteCount(8)
	}
	fs, currentLenRetrans :=  p.streamFramer.maybePopFramesForRetransmission(maxFrameSize - payloadLength - minus)
	payloadLength += currentLenRetrans

	utils.Infof("[pack]	maxframesize:%v, currentLen get from retransqueue: %v bytes, reside for normaldata: %v", maxFrameSize, currentLenRetrans, maxFrameSize - payloadLength - minus)
	
	//fs, currentLen := pth.NewPopFramesFromBuffer(maxFrameSize - payloadLength - 2)	
	fsNormal, currentLen := pth.NewPopFramesFromBuffer(maxFrameSize - payloadLength - minus)	
	utils.Infof("[pack]	currentLen get from sub_buffer: %v bytes", currentLen)
	fs = append(fs, fsNormal...)
	//fs, currentLen := f.maybePopFramesForRetransmission(maxLen)
	//return append(fs, f.maybePopNormalFrames(maxLen-currentLen, sess)...)
	// numStreams := uint32(len(pth.sess.streamsMap.streams))
	// datasize := 0
	// tmpdataforwriting := 0

	// for i := uint32(0); i < numStreams; i++ {
	// 	streamID := pth.sess.streamsMap.openStreams[i]
	// 	datasize += len(pth.sub_buffer[streamID])
	// 	tmpdataforwriting += len(pth.sess.streamsMap.streams[streamID].dataForWriting)
	//   	utils.Infof("[pack] still data in sub_buffer %v", datasize)
	// }
	// utils.Infof("[pack]dataforwriting new: %v, old:%v",tmpdataforwriting, p.lastdataforwritinglen)
	// if(p.lastdataforwritinglen != 0 && protocol.ByteCount(tmpdataforwriting) != p.lastdataforwritinglen){
	// 	utils.Infof("[pack]dataforwriting updated. exit. new: %v, old:%v",tmpdataforwriting, p.lastdataforwritinglen)
	// 	return payloadFrames, nil
	// }
	// p.lastdataforwritinglen = protocol.ByteCount(tmpdataforwriting)
	payloadLength += currentLen
	//utils.Infof("[pack-frombuffer]buffer payloadframes: %v",len(fs))		
	//utils.Infof("[pack-frombuffer]after adding from buffer payloadlength: %v", payloadLength)
	//then get normal streamframes
	//if(payloadLength < maxFrameSize  -12 && (len(pth.sub_buffer) <= 0 && currentLen != 0)){					// -12 : prevent mouse frame data produce some matter, && prevent ooo(sub_buffer have data but sending datainbuffer)
	
	// if(payloadLength < maxFrameSize  -12 && datasize <= 0 ){
	// 	utils.Infof("[pack-normal]reside for normal:%v",maxFrameSize- payloadLength )
	// 	normal := p.streamFramer.PopStreamFrames(maxFrameSize - payloadLength - 12)			//bug ???
	// 	//utils.Infof("[pack-normal]normal payloadframes: %v",normal)
	// 	fs = append(fs, normal...)
	// 	//utils.Infof("[pack]popnormal fs:%v size:%v ",len(normal),len(normal.DataLen()))
	// }
	
	if len(fs) != 0 {
		fs[len(fs)-1].DataLenPresent = false
	}

	// TODO: Simplify
	
	for _, f := range fs {
		payloadFrames = append(payloadFrames, f)
		//utils.Infof("[pack]	each frame.datalen=%v bytes, frame.off=%v", f.DataLen(), f.Offset)
	}

	for b := p.streamFramer.PopBlockedFrame(); b != nil; b = p.streamFramer.PopBlockedFrame() {
		p.controlFrames = append(p.controlFrames, b)
	}
	//utils.Infof("[pack]	this turn will send  %v payloadframes",len(payloadFrames))
	////////////////////1221 cx generate red test! !!///////////////
	// if pth.sess.config.GenerateRedundancy{
	// 	if len(payloadFrames) == 0  && pth.SendingAllowed(){					// if no payload filled but can send data, check other unavailiable path have red or not?
	// 		for pthotherID, pth_other := range pth.sess.paths {
	// 			if pth_other.SendingAllowed() || pthotherID == pth.pathID || pthotherID == protocol.InitialPathID{
	// 				continue
	// 			}
	// 			if(payloadLength < maxFrameSize - 12){					// -30: prevent mouse frame data produce some matter
	// 				utils.Infof("[pack-red-path %v]reside for redundancy:%v from path %v",pth.pathID, maxFrameSize- payloadLength, pthotherID )
	// 				red_fs, currentLen_red := pth_other.ReadRedFromBuffer(maxFrameSize - payloadLength - 12)			//bug ???
	// 				payloadLength += currentLen_red
	// 					// TODO: Simplify
	// 				for _, f := range red_fs {
	// 					payloadFrames = append(payloadFrames, f)
	// 				}
	// 			}else{
	// 				break
	// 			}
	// 		}
	// 	}
	// }
	////////////////////////////////////////////////////////////////////////
	//utils.Infof("[pack]will send  %v payloadframes this turn",len(payloadFrames))
	// compute gap and send gap to buffer
    
	// if(gap_now <= 500){
	// 	//utils.Infof("[pack] gap < 500 , small fragment no need filling ")
	// 	return payloadFrames, nil
	// }
	//utils.Infof("[pack] %v gap will be filled into sub_buffer",gap_now)
	//cx  todo: future for multi stresams 

	// cx 14 tag
	// fs = p.streamFramer.PopGap(protocol.ByteCount(gap_now), maxFrameSize - 15) 	// ???bug - 12 = PUBLIC PACKET HEADER -12 seal
	// //utils.Infof("[pack]popgap :%v ",len(fs))
	// for _, f := range fs {
	// 	pth.sub_buffer = append(pth.sub_buffer, f)
	//p.streamFramer.maybePopData(protocol.ByteCount(gap_now), pth)
	
	// }
	//utils.Infof("[pack]path %v increase sub_buffer : %v ",pth.pathID, len(pth.sub_buffer))
	//utils.Infof("[pack]payload: %v ",payloadLength)
	return payloadFrames, nil
}



func (p *packetPacker) composeNextPacket(
	maxFrameSize protocol.ByteCount,
	canSendStreamFrames bool,
	pth *path,
) ([]wire.Frame, error) {
	var payloadLength protocol.ByteCount
	var payloadFrames []wire.Frame

	// STOP_WAITING and ACK will always fit
	if p.stopWaiting[pth.pathID] != nil {
		payloadFrames = append(payloadFrames, p.stopWaiting[pth.pathID])
		l, err := p.stopWaiting[pth.pathID].MinLength(p.version)
		if err != nil {
			return nil, err
		}
		payloadLength += l
	}
	if p.ackFrame[pth.pathID] != nil {
		payloadFrames = append(payloadFrames, p.ackFrame[pth.pathID])
		l, err := p.ackFrame[pth.pathID].MinLength(p.version)
		if err != nil {
			return nil, err
		}
		payloadLength += l
	}

	for len(p.controlFrames) > 0 {
		frame := p.controlFrames[len(p.controlFrames)-1]
		minLength, err := frame.MinLength(p.version)
		if err != nil {
			return nil, err
		}
		if payloadLength+minLength > maxFrameSize {
			break
		}
		payloadFrames = append(payloadFrames, frame)
		payloadLength += minLength
		p.controlFrames = p.controlFrames[:len(p.controlFrames)-1]
	}

	if payloadLength > maxFrameSize {
		return nil, fmt.Errorf("Packet Packer BUG: packet payload (%d) too large (%d)", payloadLength, maxFrameSize)
	}

	if !canSendStreamFrames {
		return payloadFrames, nil
	}

	// temporarily increase the maxFrameSize by 2 bytes
	// this leads to a properly sized packet in all cases, since we do all the packet length calculations with StreamFrames that have the DataLen set
	// however, for the last StreamFrame in the packet, we can omit the DataLen, thus saving 2 bytes and yielding a packet of exactly the correct size
	maxFrameSize += 2

	fs := p.streamFramer.PopStreamFrames(maxFrameSize - payloadLength , pth.sess)
	//fs := p.streamFramer.PopStreamFrames(maxFrameSize - payloadLength - 9, pth.sess)
	if len(fs) != 0 {
		fs[len(fs)-1].DataLenPresent = false
	}

	// TODO: Simplify
	for _, f := range fs {
		payloadFrames = append(payloadFrames, f)
	}

	for b := p.streamFramer.PopBlockedFrame(); b != nil; b = p.streamFramer.PopBlockedFrame() {
		p.controlFrames = append(p.controlFrames, b)
	}

	return payloadFrames, nil
}



func (p *packetPacker) composeNextPacketSTMS(
	maxFrameSize protocol.ByteCount,
	canSendStreamFrames bool,
	pth *path,gap int,
) ([]wire.Frame, error) {
	var payloadLength protocol.ByteCount
	var payloadFrames []wire.Frame
	
	// STOP_WAITING and ACK will always fit
	if p.stopWaiting[pth.pathID] != nil {
		payloadFrames = append(payloadFrames, p.stopWaiting[pth.pathID])
		l, err := p.stopWaiting[pth.pathID].MinLength(p.version)
		if err != nil {
			return nil, err
		}
		payloadLength += l
	}
	if p.ackFrame[pth.pathID] != nil {
		payloadFrames = append(payloadFrames, p.ackFrame[pth.pathID])
		l, err := p.ackFrame[pth.pathID].MinLength(p.version)
		if err != nil {
			return nil, err
		}
		payloadLength += l
	}

	for len(p.controlFrames) > 0 {
		frame := p.controlFrames[len(p.controlFrames)-1]
		minLength, err := frame.MinLength(p.version)
		if err != nil {
			return nil, err
		}
		if payloadLength+minLength > maxFrameSize {
			break
		}
		payloadFrames = append(payloadFrames, frame)
		payloadLength += minLength
		p.controlFrames = p.controlFrames[:len(p.controlFrames)-1]
	}

	if payloadLength > maxFrameSize {
		return nil, fmt.Errorf("Packet Packer BUG: packet payload (%d) too large (%d)", payloadLength, maxFrameSize)
	}

	if !canSendStreamFrames {
		return payloadFrames, nil
	}

	// temporarily increase the maxFrameSize by 2 bytes
	// this leads to a properly sized packet in all cases, since we do all the packet length calculations with StreamFrames that have the DataLen set
	// however, for the last StreamFrame in the packet, we can omit the DataLen, thus saving 2 bytes and yielding a packet of exactly the correct size
	maxFrameSize += 2

	fs := p.streamFramer.PopStreamFramesSTMS(maxFrameSize - payloadLength , pth.sess, gap, pth.pathID)
	if len(fs) != 0 {
		fs[len(fs)-1].DataLenPresent = false
	}

	// TODO: Simplify
	for _, f := range fs {
		payloadFrames = append(payloadFrames, f)
	}

	for b := p.streamFramer.PopBlockedFrame(); b != nil; b = p.streamFramer.PopBlockedFrame() {
		p.controlFrames = append(p.controlFrames, b)
	}

	return payloadFrames, nil
}

func (p *packetPacker) QueueControlFrame(frame wire.Frame, pth *path) {
	switch f := frame.(type) {
	case *wire.StopWaitingFrame:
		p.stopWaiting[pth.pathID] = f
	case *wire.AckFrame:
		p.ackFrame[pth.pathID] = f
	default:
		p.controlFrames = append(p.controlFrames, f)
	}
}

func (p *packetPacker) getPublicHeader(encLevel protocol.EncryptionLevel, pth *path) *wire.PublicHeader {
	pnum := pth.packetNumberGenerator.Peek()
	packetNumberLen := protocol.GetPacketNumberLengthForPublicHeader(pnum, pth.leastUnacked)
	publicHeader := &wire.PublicHeader{
		ConnectionID:         p.connectionID,
		PacketNumber:         pnum,
		PacketNumberLen:      packetNumberLen,
		TruncateConnectionID: p.connectionParameters.TruncateConnectionID(),
	}

	if p.perspective == protocol.PerspectiveServer && encLevel == protocol.EncryptionSecure {
		publicHeader.DiversificationNonce = p.cryptoSetup.DiversificationNonce()
	}
	if p.perspective == protocol.PerspectiveClient && encLevel != protocol.EncryptionForwardSecure {
		publicHeader.VersionFlag = true
		publicHeader.VersionNumber = p.version
	}

	// XXX (QDC): need a additional check because of tests
	if pth.sess != nil && pth.sess.handshakeComplete && p.version >= protocol.VersionMP {
		publicHeader.MultipathFlag = true
		publicHeader.PathID = pth.pathID
		// XXX (QDC): in case of doubt, never truncate the connection ID. This might change...
		publicHeader.TruncateConnectionID = false
	}

	return publicHeader
}

func (p *packetPacker) writeAndSealPacket(
	publicHeader *wire.PublicHeader,
	payloadFrames []wire.Frame,
	sealer handshake.Sealer,
	pth *path,
) ([]byte, error) {
	raw := getPacketBuffer()
	buffer := bytes.NewBuffer(raw)
	//utils.Infof("[pack]bufferlen origin%v",buffer.Len())
	if err := publicHeader.Write(buffer, p.version, p.perspective); err != nil {
		
		return nil, err
	}
	
	//utils.Infof("[pack]bufferlen after header %v",buffer.Len())
	payloadStartIndex := buffer.Len()
	for _, frame := range payloadFrames {
		err := frame.Write(buffer, p.version)
		//frameHeaderBytes,_ :=  frame.MinLength(protocol.VersionWhatever) 
		//utils.Infof("[pack]bufferlen frame %v, headerlen:%v", buffer.Len(), frameHeaderBytes)
		if err != nil {
			return nil, err
		}
	}
	//utils.Infof("[pack]buffer: %v, seal: %v", buffer.Len(), sealer.Overhead())
	if protocol.ByteCount(buffer.Len()+sealer.Overhead()) > protocol.MaxPacketSize {
		utils.Infof("[pack]error maxpktsize:%v, but real content size:%v",protocol.MaxPacketSize,protocol.ByteCount(buffer.Len()+sealer.Overhead()))
		//return nil, errors.New("PacketPacker BUG: packet too large")
		return nil,nil				//cx add 1219 remove error
	}

	raw = raw[0:buffer.Len()]
	_ = sealer.Seal(raw[payloadStartIndex:payloadStartIndex], raw[payloadStartIndex:], publicHeader.PacketNumber, raw[:payloadStartIndex])
	raw = raw[0 : buffer.Len()+sealer.Overhead()]
	num := pth.packetNumberGenerator.Pop()
	if num != publicHeader.PacketNumber {
		return nil, errors.New("packetPacker BUG: Peeked and Popped packet numbers do not match")
	}

	return raw, nil
}

func (p *packetPacker) canSendData(encLevel protocol.EncryptionLevel) bool {
	if p.perspective == protocol.PerspectiveClient {
		return encLevel >= protocol.EncryptionSecure
	}
	return encLevel == protocol.EncryptionForwardSecure
}
