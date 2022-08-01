package quic

import (
	"time"
	//"fmt"
	"sync"
	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type scheduler struct {
	// XXX Currently round-robin based, inspired from MPTCP scheduler
	quotas map[protocol.PathID]uint
	SchedulerName string
	OriginScheduler string
	waiting    uint64
	redundancy protocol.ByteCount
	redundancy_data []byte
	redundancy_stream_off_start protocol.ByteCount
	redundancy_stream_off_end protocol.ByteCount
	monitor *monitor
	// Flag of current network status
	Flag_beginining bool
	Flag_bw_unenough bool
	Flag_high_lossrate bool

	lastpath protocol.PathID


	delta_gap map[protocol.PathID]int
	totalruntime int64
	totalpacketnum int64
	CWNDFlag bool				// cx designed for always no cwnd control, but now abandon it.
}
type monitor struct{
	// separate path statis

	mutex sync.Mutex

	state_owd map[protocol.PathID] time.Duration
	state_bw map[protocol.PathID] int64
	state_cwnd map[protocol.PathID] int64
	state_loss  map[protocol.PathID] float64
	state_inflight map[protocol.PathID] int64
	state_serverinx map[protocol.PathID] int64
	// whole network statis
	totalbw float64
	lackbw bool
	totalcwnd int64
	retransBytes protocol.ByteCount

	//content analyzer
	bitrate float64
	fps float64

	
}

func (m *monitor) setup() {
	m.state_owd = make(map[protocol.PathID] time.Duration)
	m.state_bw = make(map[protocol.PathID] int64)
	m.state_cwnd = make(map[protocol.PathID] int64)
	m.state_loss = make(map[protocol.PathID] float64)
	m.state_inflight = make(map[protocol.PathID] int64)
	m.state_serverinx = make(map[protocol.PathID] int64)
	m.totalbw = 0
	m.fps = 25
	m.bitrate = ( 18504 * 1000 ) / 8 
	m.lackbw = false


}

func (sch *scheduler) setup() {
	sch.CWNDFlag = false
	sch.OriginScheduler = sch.SchedulerName
	sch.quotas = make(map[protocol.PathID]uint)
	sch.waiting = 0
	sch.redundancy = 0
	sch.monitor = &monitor{}
	sch.monitor.setup()
	//sch.redundancy_data = make([]byte)
	sch.delta_gap = make(map[protocol.PathID]int)
	sch.totalruntime = 0
	sch.totalpacketnum = 0
	sch.lastpath = 1
}


func (sch *scheduler) getRetransmission(s *session) (hasRetransmission bool, retransmitPacket *ackhandler.Packet, pth *path) {
	// check for retransmissions first
	for {
		// TODO add ability to reinject on another path
		// XXX We need to check on ALL paths if any packet should be first retransmitted
		s.pathsLock.RLock()
	retransmitLoop:
		for _, pthTmp := range s.paths {
			retransmitPacket = pthTmp.sentPacketHandler.DequeuePacketForRetransmission()
			if retransmitPacket != nil {
				pth = pthTmp
				break retransmitLoop
			}
		}
		s.pathsLock.RUnlock()
		if retransmitPacket == nil {
			break
		}
		hasRetransmission = true

		if retransmitPacket.EncryptionLevel != protocol.EncryptionForwardSecure {
			if s.handshakeComplete {
				// Don't retransmit handshake packets when the handshake is complete
				continue
			}
			utils.Debugf("\tDequeueing handshake retransmission for packet 0x%x", retransmitPacket.PacketNumber)
			return
		}
		utils.Debugf("\tDequeueing retransmission of packet 0x%x from path %d", retransmitPacket.PacketNumber, pth.pathID)
		// resend the frames that were in the packet
		for _, frame := range retransmitPacket.GetFramesForRetransmission() {
			switch f := frame.(type) {
			case *wire.StreamFrame:
				s.streamFramer.AddFrameForRetransmission(f)
			case *wire.WindowUpdateFrame:
				// only retransmit WindowUpdates if the stream is not yet closed and the we haven't sent another WindowUpdate with a higher ByteOffset for the stream
				// XXX Should it be adapted to multiple paths?
				currentOffset, err := s.flowControlManager.GetReceiveWindow(f.StreamID)
				if err == nil && f.ByteOffset >= currentOffset {
					s.packer.QueueControlFrame(f, pth)
				}
			case *wire.PathsFrame:
				// Schedule a new PATHS frame to send
				s.schedulePathsFrame()
			default:
				s.packer.QueueControlFrame(frame, pth)
			}
		}
	}
	return
}

func (sch *scheduler) selectPathRoundRobin(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	if sch.quotas == nil {
		sch.setup()
	}

	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed(sch.CWNDFlag) {
			return nil
		}
		return s.paths[protocol.InitialPathID]
	}

	// TODO cope with decreasing number of paths (needed?)
	var selectedPath *path
	var lowerQuota, currentQuota uint
	var ok bool

	// Max possible value for lowerQuota at the beginning
	lowerQuota = ^uint(0)

pathLoop:
	for pathID, pth := range s.paths {
		// Don't block path usage if we retransmit, even on another path
		if !hasRetransmission && !pth.SendingAllowed(sch.CWNDFlag) {
		//if !hasRetransmission && !sch.CWNDFlag {
			continue pathLoop
		}

		// If this path is potentially failed, do no consider it for sending
		if pth.potentiallyFailed.Get() {
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		currentQuota, ok = sch.quotas[pathID]
		if !ok {
			sch.quotas[pathID] = 0
			currentQuota = 0
		}

		if currentQuota < lowerQuota {
			selectedPath = pth
			lowerQuota = currentQuota
		}
	}

	return selectedPath

}



func (sch *scheduler) selectPathDispatch(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	var sndPath *path
	if sch.quotas == nil {
		sch.setup()
	}

	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed(sch.CWNDFlag) {
			return nil
		}
		return s.paths[protocol.InitialPathID]
	}

	var selectedPath *path


pathLoop:
	for pathID, pth := range s.paths {
		// Don't block path usage if we retransmit, even on another path
		if !hasRetransmission && !pth.SendingAllowed(sch.CWNDFlag) {
		//if !hasRetransmission && !sch.CWNDFlag {
			continue pathLoop
		}

		// If this path is potentially failed, do no consider it for sending
		if pth.potentiallyFailed.Get() {
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		if pathID ==  sch.lastpath {
			sndPath = pth
	
		}else{
			selectedPath = pth
		}
	}
	if selectedPath != nil {
		sch.lastpath = selectedPath.pathID
	}else if selectedPath == nil && sndPath != nil{
		sch.lastpath = sndPath.pathID 
		selectedPath = sndPath
	}
	utils.Infof("select path %v,",selectedPath)
	return selectedPath

}

func (sch *scheduler) selectPathLowLatency(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed(sch.CWNDFlag) {
			return nil
		}
		return s.paths[protocol.InitialPathID]
	}

	// FIXME Only works at the beginning... Cope with new paths during the connection
	if hasRetransmission && hasStreamRetransmission && fromPth.rttStats.SmoothedRTT() == 0 {
		// Is there any other path with a lower number of packet sent?
		currentQuota := sch.quotas[fromPth.pathID]
		for pathID, pth := range s.paths {
			if pathID == protocol.InitialPathID || pathID == fromPth.pathID {
				continue
			}
			// The congestion window was checked when duplicating the packet
			if sch.quotas[pathID] < currentQuota {
				return pth
			}
		}
	}

	var selectedPath *path
	var lowerRTT time.Duration
	var currentRTT time.Duration
	selectedPathID := protocol.PathID(255)

pathLoop:
	for pathID, pth := range s.paths {
		// Don't block path usage if we retransmit, even on another path
		if !hasRetransmission && !pth.SendingAllowed(sch.CWNDFlag) {
			utils.Debugf("path :%d\n", pathID)
			continue pathLoop
		}

		// If this path is potentially failed, do not consider it for sending
		if pth.potentiallyFailed.Get() {
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		currentRTT = pth.rttStats.SmoothedRTT()

		// Prefer staying single-path if not blocked by current path
		// Don't consider this sample if the smoothed RTT is 0
		if lowerRTT != 0 && currentRTT == 0 {
			continue pathLoop
		}

		// Case if we have multiple paths unprobed
		if currentRTT == 0 {
			currentQuota, ok := sch.quotas[pathID]
			if !ok {
				sch.quotas[pathID] = 0
				currentQuota = 0
			}
			lowerQuota, _ := sch.quotas[selectedPathID]
			if selectedPath != nil && currentQuota > lowerQuota {
				continue pathLoop
			}
		}

		if currentRTT != 0 && lowerRTT != 0 && selectedPath != nil && currentRTT >= lowerRTT {
			continue pathLoop
		}

		// Update
		lowerRTT = currentRTT
		selectedPath = pth
		selectedPathID = pathID
	}

	return selectedPath
}

func (sch *scheduler) selectPathLowLoss(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed(sch.CWNDFlag) {
			return nil
		}
		return s.paths[protocol.InitialPathID]
	}

	// FIXME Only works at the beginning... Cope with new paths during the connection
	if hasRetransmission && hasStreamRetransmission && fromPth.rttStats.SmoothedRTT() == 0 {
		// Is there any other path with a lower number of packet sent?
		currentQuota := sch.quotas[fromPth.pathID]
		for pathID, pth := range s.paths {
			if pathID == protocol.InitialPathID || pathID == fromPth.pathID {
				continue
			}
			// The congestion window was checked when duplicating the packet
			if sch.quotas[pathID] < currentQuota {
				return pth
			}
		}
	}

	var selectedPath *path
	var lowerLOSS float64
	var currentLOSS float64
	var currentRTT time.Duration
	var lowerRTT time.Duration
	selectedPathID := protocol.PathID(255)
	lowerLOSS = 100
	lowerRTT = time.Duration(100000000000)
pathLoop:
	for pathID, pth := range s.paths {
		// Don't block path usage if we retransmit, even on another path
		if !hasRetransmission && !pth.SendingAllowed(sch.CWNDFlag) {
			utils.Debugf("path :%d\n", pathID)
			continue pathLoop
		}

		// If this path is potentially failed, do not consider it for sending
		if pth.potentiallyFailed.Get() {
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		currentLOSS = sch.monitor.state_loss[pathID]
		currentRTT = pth.rttStats.SmoothedRTT()
		// Prefer staying single-path if not blocked by current path
		// Don't consider this sample if the smoothed RTT is 0
		// if lowerLOSS != 0 && currentLOSS == 0 {
		// 	continue pathLoop
		// }
		utils.Infof("[sch-loss] currtt :%v, curloss:%v, lowerLOss:%v", currentRTT,currentLOSS, lowerLOSS)
		if (currentRTT != 0 && currentLOSS == 0) || (currentRTT != 0 && currentLOSS <= lowerLOSS) {
			if(currentLOSS == lowerLOSS && currentRTT > lowerRTT){
				continue pathLoop
			}
			lowerLOSS = currentLOSS
			lowerRTT = currentRTT
			selectedPath = pth
			selectedPathID = pathID
			//utils.Infof("[sch-loss] hi")
		}
		// Case if we have multiple paths unprobed
		
		if currentRTT == 0 {
			currentQuota, ok := sch.quotas[pathID]
			if !ok {
				sch.quotas[pathID] = 0
				currentQuota = 0
			}
			lowerQuota, _ := sch.quotas[selectedPathID]
			if selectedPath != nil && currentQuota > lowerQuota {
				continue pathLoop
			}
		}

		// if currentLOSS != 0 && lowerLOSS != 0 && selectedPath != nil && currentLOSS >= lowerLOSS {
		// 	continue pathLoop
		// }

		// // Update
		// lowerLOSS = currentLOSS
		// selectedPath = pth
		// selectedPathID = pathID
	}
	utils.Infof("[sch-loss] %v",selectedPathID)
	return selectedPath
}

func (sch *scheduler) selectBLEST(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed(sch.CWNDFlag) {
			return nil
		}
		return s.paths[protocol.InitialPathID]
	}

	// FIXME Only works at the beginning... Cope with new paths during the connection
	if hasRetransmission && hasStreamRetransmission && fromPth.rttStats.SmoothedRTT() == 0 {
		// Is there any other path with a lower number of packet sent?
		currentQuota := sch.quotas[fromPth.pathID]
		for pathID, pth := range s.paths {
			if pathID == protocol.InitialPathID || pathID == fromPth.pathID {
				continue
			}
			// The congestion window was checked when duplicating the packet
			if sch.quotas[pathID] < currentQuota {
				return pth
			}
		}
	}

	var bestPath *path
	var secondBestPath *path
	var lowerRTT time.Duration
	var currentRTT time.Duration
	var secondLowerRTT time.Duration
	bestPathID := protocol.PathID(255)

pathLoop:
	for pathID, pth := range s.paths {
		// Don't block path usage if we retransmit, even on another path
		if !hasRetransmission && !pth.SendingAllowed(sch.CWNDFlag) {
			continue pathLoop
		}

		// If this path is potentially failed, do not consider it for sending
		if pth.potentiallyFailed.Get() {
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		currentRTT = pth.rttStats.SmoothedRTT()

		// Prefer staying single-path if not blocked by current path
		// Don't consider this sample if the smoothed RTT is 0
		if lowerRTT != 0 && currentRTT == 0 {
			continue pathLoop
		}

		// Case if we have multiple paths unprobed
		if currentRTT == 0 {
			currentQuota, ok := sch.quotas[pathID]
			if !ok {
				sch.quotas[pathID] = 0
				currentQuota = 0
			}
			lowerQuota, _ := sch.quotas[bestPathID]
			if bestPath != nil && currentQuota > lowerQuota {
				continue pathLoop
			}
		}

		if currentRTT >= lowerRTT {
			if (secondLowerRTT == 0 || currentRTT < secondLowerRTT) && pth.SendingAllowed(sch.CWNDFlag) {
				// Update second best available path
				secondLowerRTT = currentRTT
				secondBestPath = pth
			}
			if currentRTT != 0 && lowerRTT != 0 && bestPath != nil {
				continue pathLoop
			}
		}

		// Update
		lowerRTT = currentRTT
		bestPath = pth
		bestPathID = pathID
	}

	if bestPath == nil {
		if secondBestPath != nil {
			return secondBestPath
		}
		return nil
	}

	if hasRetransmission || bestPath.SendingAllowed(sch.CWNDFlag) {
		return bestPath
	}

	if secondBestPath == nil {
		return nil
	}
	cwndBest := uint64(bestPath.sentPacketHandler.GetCWND())
	FirstCo := uint64(protocol.DefaultTCPMSS) * uint64(secondLowerRTT) * (cwndBest*2*uint64(lowerRTT) + uint64(secondLowerRTT) - uint64(lowerRTT))
	BSend, _ := s.flowControlManager.SendWindowSize(protocol.StreamID(5))
	SecondCo := 2 * 1 * uint64(lowerRTT) * uint64(lowerRTT) * (uint64(BSend) - (uint64(secondBestPath.sentPacketHandler.GetBytesInflight())+uint64(protocol.DefaultTCPMSS)))

	if (FirstCo > SecondCo) {
		return nil		
	} else {
		return secondBestPath
	}
}

func (sch *scheduler) selectECF(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed(sch.CWNDFlag) {
			return nil
		}
		return s.paths[protocol.InitialPathID]
	}

	// FIXME Only works at the beginning... Cope with new paths during the connection
	if hasRetransmission && hasStreamRetransmission && fromPth.rttStats.SmoothedRTT() == 0 {
		// Is there any other path with a lower number of packet sent?
		currentQuota := sch.quotas[fromPth.pathID]
		for pathID, pth := range s.paths {
			if pathID == protocol.InitialPathID || pathID == fromPth.pathID {
				continue
			}
			// The congestion window was checked when duplicating the packet
			if sch.quotas[pathID] < currentQuota {
				return pth
			}
		}
	}

	var bestPath *path
	var secondBestPath *path
	var lowerRTT time.Duration
	var currentRTT time.Duration
	var secondLowerRTT time.Duration
	bestPathID := protocol.PathID(255)

pathLoop:
	for pathID, pth := range s.paths {
		// Don't block path usage if we retransmit, even on another path
		if !hasRetransmission && !pth.SendingAllowed(sch.CWNDFlag) {
			continue pathLoop
		}

		// If this path is potentially failed, do not consider it for sending
		if pth.potentiallyFailed.Get() {
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		currentRTT = pth.rttStats.SmoothedRTT()

		// Prefer staying single-path if not blocked by current path
		// Don't consider this sample if the smoothed RTT is 0
		if lowerRTT != 0 && currentRTT == 0 {
			continue pathLoop
		}

		// Case if we have multiple paths unprobed
		if currentRTT == 0 {
			currentQuota, ok := sch.quotas[pathID]
			if !ok {
				sch.quotas[pathID] = 0
				currentQuota = 0
			}
			lowerQuota, _ := sch.quotas[bestPathID]
			if bestPath != nil && currentQuota > lowerQuota {
				continue pathLoop
			}
		}

		if currentRTT >= lowerRTT {
			if (secondLowerRTT == 0 || currentRTT < secondLowerRTT) && pth.SendingAllowed(sch.CWNDFlag) {
				// Update second best available path
				secondLowerRTT = currentRTT
				secondBestPath = pth
			}
			if currentRTT != 0 && lowerRTT != 0 && bestPath != nil {
				continue pathLoop
			}
		}

		// Update
		lowerRTT = currentRTT
		bestPath = pth
		bestPathID = pathID
	}

	if bestPath == nil {
		if secondBestPath != nil {
			return secondBestPath
		}
		return nil
	}

	if hasRetransmission || bestPath.SendingAllowed(sch.CWNDFlag) {
		return bestPath
	}

	if secondBestPath == nil {
		return nil
	}

	var queueSize uint64
	getQueueSize := func(s *stream) (bool, error) {
		if s != nil {
			queueSize = queueSize + uint64(s.lenOfDataForWriting())
		}
		return true, nil
	}
	s.streamsMap.Iterate(getQueueSize)

	cwndBest := uint64(bestPath.sentPacketHandler.GetCWND())
	cwndSecond := uint64(secondBestPath.sentPacketHandler.GetCWND())
	deviationBest := uint64(bestPath.rttStats.MeanDeviation())
	deviationSecond := uint64(secondBestPath.rttStats.MeanDeviation())

	delta := deviationBest
	if deviationBest < deviationSecond {
		delta = deviationSecond
	}
	xBest := queueSize
	if queueSize < cwndBest {
		xBest = cwndBest
	}

	lhs := uint64(lowerRTT) * (xBest + cwndBest)
	rhs := cwndBest * (uint64(secondLowerRTT) + delta)
	if (lhs * 4) < ((rhs * 4) + sch.waiting*rhs){
		xSecond := queueSize
		if queueSize < cwndSecond {
			xSecond = cwndSecond
		}
		lhsSecond := uint64(secondLowerRTT) * xSecond
		rhsSecond := cwndSecond * (2*uint64(lowerRTT) + delta)
		if (lhsSecond > rhsSecond) {
				sch.waiting = 1
			    return nil
		} 
	} else {
		sch.waiting = 0
	}

	return secondBestPath
}


func (sch *scheduler) computeHeterDegree(s *session) float64{
	// todo: compute the hetergenouse degree of multiple paths
	maxOWD := float64(0)
	minOWD := float64(99999)
	maxBW := float64(0)
	minBW := float64(99999)
	alpha := float64(100)
	beta := float64(1)
	for _, pth := range s.paths {
		OWD := float64(pth.rttStats.SmoothedRTT().Seconds() / 2)
		BW := float64(pth.sentPacketHandler.GetBandwidthEstimate() / 1000000)
		if OWD > maxOWD{
			maxOWD = OWD
		}
		if OWD < minOWD{
			minOWD = OWD
		}
		if BW > maxBW{
			maxBW = BW
		}
		if BW < minBW{
			minBW = BW
		}
	}
	hete := float64(alpha * (maxOWD - minOWD) + beta * (maxBW - minBW))
	utils.Infof("[sch-ss] heter:%v",hete)
	return hete
}

//cx add
func (sch *scheduler) selectPathMoooKO(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	return nil
}
// Lock of s.paths must be held
func (sch *scheduler) selectPath(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	// XXX Currently round-robin
	// TODO select the right scheduler dynamically
	//fmt.Println(sch.SchedulerName)
	if sch.SchedulerName == "rtt" {
		
		return sch.selectPathLowLatency(s, hasRetransmission, hasStreamRetransmission, fromPth)
	}else if sch.SchedulerName == "rr"{	
		return sch.selectPathRoundRobin(s, hasRetransmission, hasStreamRetransmission, fromPth)
	}else if sch.SchedulerName ==  "blest"{                                   //keep ordering algorithm
		return sch.selectBLEST(s, hasRetransmission, hasStreamRetransmission, fromPth)
	}else if sch.SchedulerName ==  "ecf"{                                   //keep ordering algorithm
		return sch.selectECF(s, hasRetransmission, hasStreamRetransmission, fromPth)
	}else if sch.SchedulerName ==  "moooko"{                                   //keep ordering algorithm
		return sch.selectPathLowLatency(s, hasRetransmission, hasStreamRetransmission, fromPth)
	}else if sch.SchedulerName == "moooss"{                                    //select scheduler algorithm
		heter_threshold := float64(50)
		diff := sch.computeHeterDegree(s)
        if diff < heter_threshold {                                              
			return sch.selectPathRoundRobin(s, hasRetransmission, hasStreamRetransmission, fromPth)
		}else{
			return sch.selectPathLowLatency(s, hasRetransmission, hasStreamRetransmission, fromPth)
		}
	}else{
		//fmt.Println("select else rtt")
		return sch.selectPathLowLatency(s, hasRetransmission, hasStreamRetransmission, fromPth)
		
		//return nil
	}
}

// cx add: traditional performpacketsending only send into one path this time
func (sch *scheduler) performPacketSendingSTMS(s *session, windowUpdateFrames []*wire.WindowUpdateFrame, pth *path, gap int) (*ackhandler.Packet, bool, error) {
	// add a retransmittable frame
	if pth.sentPacketHandler.ShouldSendRetransmittablePacket() {
		s.packer.QueueControlFrame(&wire.PingFrame{}, pth)
	}
	
	packet, err := s.packer.PackPacketSTMS(pth, gap)
	if err != nil || packet == nil {
		return nil, false, err
	}
	if err = s.sendPackedPacket(packet, pth, true); err != nil {
		return nil, false, err
	}

	// send every window update twice
	for _, f := range windowUpdateFrames {
		s.packer.QueueControlFrame(f, pth)
	}

	// Packet sent, so update its quota
	sch.quotas[pth.pathID]++

	// Provide some logging if it is the last packet
	for _, frame := range packet.frames {
		switch frame := frame.(type) {
		case *wire.StreamFrame:
			if frame.FinBit {
				// Last packet to send on the stream, print stats
				s.pathsLock.RLock()
				utils.Infof("Info for stream %x of %x", frame.StreamID, s.connectionID)
				for pathID, pth := range s.paths {
					sntPkts, sntRetrans, sntLost := pth.sentPacketHandler.GetStatistics()
					rcvPkts := pth.receivedPacketHandler.GetStatistics()
					utils.Infof("Path %x: sent %d retrans %d lost %d; rcv %d rtt %v local:%s remote:%s", pathID, sntPkts, sntRetrans, sntLost, rcvPkts, pth.rttStats.SmoothedRTT(), pth.conn.LocalAddr(), pth.conn.RemoteAddr())
				}
				s.pathsLock.RUnlock()
			}
		default:
		}
	}

	pkt := &ackhandler.Packet{
		PacketNumber:    packet.number,
		Frames:          packet.frames,
		Length:          protocol.ByteCount(len(packet.raw)),
		EncryptionLevel: packet.encryptionLevel,
	}

	return pkt, true, nil
}
func  (sch *scheduler)performPacketSendingMOOO(s *session, windowUpdateFrames []*wire.WindowUpdateFrame, pth *path, gap map[uint8] int) (*ackhandler.Packet, bool, error) {
	// add a retransmittable frame
	if pth.sentPacketHandler.ShouldSendRetransmittablePacket() {
		s.packer.QueueControlFrame(&wire.PingFrame{}, pth)
	}

	packet, err := s.packer.PackPacketMOOO(pth,gap)
	if err != nil || packet == nil {
		utils.Infof("[sc]pack err %v",err)
		return nil, false, err
	}

	
	if err = s.sendPackedPacket(packet, pth, true); err != nil {
		utils.Infof("[sc]sent err %v", err)
		return nil, false, err
	}

	// send every window update twice
	for _, f := range windowUpdateFrames {
		s.packer.QueueControlFrame(f, pth)
	}

	// Packet sent, so update its quota
	sch.quotas[pth.pathID]++

	// Provide some logging if it is the last packet
	for _, frame := range packet.frames {
		switch frame := frame.(type) {
		case *wire.StreamFrame:
			if frame.FinBit {
				// Last packet to send on the stream, print stats
				s.pathsLock.RLock()
				utils.Infof("Info for stream %x of %x", frame.StreamID, s.connectionID)
				for pathID, pth := range s.paths {
					sntPkts, sntRetrans, sntLost := pth.sentPacketHandler.GetStatistics()
					rcvPkts := pth.receivedPacketHandler.GetStatistics()
					utils.Infof("Path %x: sent %d retrans %d lost %d; rcv %d rtt %v local:%s remote:%s", pathID, sntPkts, sntRetrans, sntLost, rcvPkts, pth.rttStats.SmoothedRTT(), pth.conn.LocalAddr(), pth.conn.RemoteAddr())
				}
				s.pathsLock.RUnlock()
			}
		default:
		}
	}

	pkt := &ackhandler.Packet{
		PacketNumber:    packet.number,
		Frames:          packet.frames,
		Length:          protocol.ByteCount(len(packet.raw)),
		EncryptionLevel: packet.encryptionLevel,
	}

	return pkt, true, nil
}

func (sch *scheduler)performPacketSendingRedundancy(s *session, windowUpdateFrames []*wire.WindowUpdateFrame, pth *path, isfirst bool) (*ackhandler.Packet, bool, error) {
	// add a retransmittable frame
	if pth.sentPacketHandler.ShouldSendRetransmittablePacket() {
		s.packer.QueueControlFrame(&wire.PingFrame{}, pth)
	}
	packet, err := s.packer.PackPacketRedundancy(pth,isfirst)
	if err != nil || packet == nil {
		return nil, false, err
	}
	
	if err = s.sendPackedPacket(packet, pth, isfirst); err != nil {
		return nil, false, err
	}

	// send every window update twice
	for _, f := range windowUpdateFrames {
		s.packer.QueueControlFrame(f, pth)
	}

	// Packet sent, so update its quota
	sch.quotas[pth.pathID]++

	// Provide some logging if it is the last packet
	for _, frame := range packet.frames {
		switch frame := frame.(type) {
		case *wire.StreamFrame:
			if frame.FinBit {
				// Last packet to send on the stream, print stats
				s.pathsLock.RLock()
				utils.Infof("Info for stream %x of %x", frame.StreamID, s.connectionID)
				for pathID, pth := range s.paths {
					sntPkts, sntRetrans, sntLost := pth.sentPacketHandler.GetStatistics()
					rcvPkts := pth.receivedPacketHandler.GetStatistics()
					utils.Infof("Path %x: sent %d retrans %d lost %d; rcv %d rtt %v local:%s remote:%s", pathID, sntPkts, sntRetrans, sntLost, rcvPkts, pth.rttStats.SmoothedRTT(), pth.conn.LocalAddr(), pth.conn.RemoteAddr())
				}
				s.pathsLock.RUnlock()
			}
		default:
		}
	}

	pkt := &ackhandler.Packet{
		PacketNumber:    packet.number,
		Frames:          packet.frames,
		Length:          protocol.ByteCount(len(packet.raw)),
		EncryptionLevel: packet.encryptionLevel,
	}

	return pkt, true, nil
}


// Complete Redundancy(RDDT) for comparision
func (sch *scheduler)performPacketSendingRDDT(s *session, windowUpdateFrames []*wire.WindowUpdateFrame, pth *path, isfirst bool) (*ackhandler.Packet, bool, error) {
	// add a retransmittable frame
	if pth.sentPacketHandler.ShouldSendRetransmittablePacket() {
		s.packer.QueueControlFrame(&wire.PingFrame{}, pth)
	}
	packet, err := s.packer.PackPacketRedundancy(pth,isfirst)
	if err != nil || packet == nil {
		return nil, false, err
	}
	// only this line different from duplicate
	if err = s.sendPackedPacket(packet, pth, true); err != nil {
		return nil, false, err
	}

	// send every window update twice
	for _, f := range windowUpdateFrames {
		s.packer.QueueControlFrame(f, pth)
	}

	// Packet sent, so update its quota
	sch.quotas[pth.pathID]++

	// Provide some logging if it is the last packet
	for _, frame := range packet.frames {
		switch frame := frame.(type) {
		case *wire.StreamFrame:
			if frame.FinBit {
				// Last packet to send on the stream, print stats
				s.pathsLock.RLock()
				utils.Infof("Info for stream %x of %x", frame.StreamID, s.connectionID)
				for pathID, pth := range s.paths {
					sntPkts, sntRetrans, sntLost := pth.sentPacketHandler.GetStatistics()
					rcvPkts := pth.receivedPacketHandler.GetStatistics()
					utils.Infof("Path %x: sent %d retrans %d lost %d; rcv %d rtt %v local:%s remote:%s", pathID, sntPkts, sntRetrans, sntLost, rcvPkts, pth.rttStats.SmoothedRTT(), pth.conn.LocalAddr(), pth.conn.RemoteAddr())
				}
				s.pathsLock.RUnlock()
			}
		default:
		}
	}

	pkt := &ackhandler.Packet{
		PacketNumber:    packet.number,
		Frames:          packet.frames,
		Length:          protocol.ByteCount(len(packet.raw)),
		EncryptionLevel: packet.encryptionLevel,
	}

	return pkt, true, nil
}
// Lock of s.paths must be free (in case of log print)
func (sch *scheduler) performPacketSending(s *session, windowUpdateFrames []*wire.WindowUpdateFrame, pth *path) (*ackhandler.Packet, bool, error) {
	// add a retransmittable frame
	if pth.sentPacketHandler.ShouldSendRetransmittablePacket() {
		s.packer.QueueControlFrame(&wire.PingFrame{}, pth)
	}
	packet, err := s.packer.PackPacket(pth)
	if err != nil || packet == nil {
		return nil, false, err
	}
	if err = s.sendPackedPacket(packet, pth, true); err != nil {
		return nil, false, err
	}

	// send every window update twice
	for _, f := range windowUpdateFrames {
		s.packer.QueueControlFrame(f, pth)
	}

	// Packet sent, so update its quota
	sch.quotas[pth.pathID]++

	// Provide some logging if it is the last packet
	for _, frame := range packet.frames {
		switch frame := frame.(type) {
		case *wire.StreamFrame:
			if frame.FinBit {
				// Last packet to send on the stream, print stats
				s.pathsLock.RLock()
				utils.Infof("Info for stream %x of %x", frame.StreamID, s.connectionID)
				for pathID, pth := range s.paths {
					sntPkts, sntRetrans, sntLost := pth.sentPacketHandler.GetStatistics()
					rcvPkts := pth.receivedPacketHandler.GetStatistics()
					utils.Infof("Path %x: sent %d retrans %d lost %d; rcv %d rtt %v local:%s remote:%s", pathID, sntPkts, sntRetrans, sntLost, rcvPkts, pth.rttStats.SmoothedRTT(), pth.conn.LocalAddr(), pth.conn.RemoteAddr())
				}
				s.pathsLock.RUnlock()
			}
		default:
		}
	}

	pkt := &ackhandler.Packet{
		PacketNumber:    packet.number,
		Frames:          packet.frames,
		Length:          protocol.ByteCount(len(packet.raw)),
		EncryptionLevel: packet.encryptionLevel,
	}

	return pkt, true, nil
}

// Lock of s.paths must be free
func (sch *scheduler) ackRemainingPaths(s *session, totalWindowUpdateFrames []*wire.WindowUpdateFrame) error {
	// Either we run out of data, or CWIN of usable paths are full
	// Send ACKs on paths not yet used, if needed. Either we have no data to send and
	// it will be a pure ACK, or we will have data in it, but the CWIN should then
	// not be an issue.
	s.pathsLock.RLock()
	defer s.pathsLock.RUnlock()
	// get WindowUpdate frames
	// this call triggers the flow controller to increase the flow control windows, if necessary
	windowUpdateFrames := totalWindowUpdateFrames
	if len(windowUpdateFrames) == 0 {
		windowUpdateFrames = s.getWindowUpdateFrames(s.peerBlocked)
	}
	for _, pthTmp := range s.paths {
		ackTmp := pthTmp.GetAckFrame()
		for _, wuf := range windowUpdateFrames {
			s.packer.QueueControlFrame(wuf, pthTmp)
		}
		if ackTmp != nil || len(windowUpdateFrames) > 0 {
			if pthTmp.pathID == protocol.InitialPathID && ackTmp == nil {
				continue
			}
			swf := pthTmp.GetStopWaitingFrame(false)
			if swf != nil {
				s.packer.QueueControlFrame(swf, pthTmp)
			}
			s.packer.QueueControlFrame(ackTmp, pthTmp)
			// XXX (QDC) should we instead call PackPacket to provides WUFs?
			var packet *packedPacket
			var err error
			if ackTmp != nil {
				// Avoid internal error bug
				packet, err = s.packer.PackAckPacket(pthTmp)
			} else {
				packet, err = s.packer.PackPacket(pthTmp)
			}
			if err != nil {
				return err
			}
			err = s.sendPackedPacket(packet, pthTmp,true)
			if err != nil {
				return err
			}
		}
	}
	s.peerBlocked = false
	return nil
}
//cx add 1221 for redundancy generation
func (sch *scheduler) generateRedundancy(s *session, state map[protocol.PathID] int64) {
	// 1. get dataforwriting now
	streams := s.streamsMap.streams
	var datasize int
	//var redundancy int
	//var space int64
	for i := uint32(0) ; i < uint32(len(streams)) ;i++{
		streamID := s.streamsMap.openStreams[i]
		str, _:= streams[streamID]
		datasize += len(str.dataForWriting)
	}
	utils.Infof("[str]unsentDataSize:%v",datasize)
	// 2. get cwnd - inflight now
	
	// for pathID, _ := range s.paths {
	// 	space += state[pathID]
	// }
	// 3. compute the redundant cwnd resource
	//redundancy = int(space) - datasize
	//utils.Infof("[str]reserved space: %v",redundancy)
	// 4. send sub_buffer data into lower RTT paths.(how ? I? )
}


//cx add 1213
func (sch *scheduler) sendPacketMooo(s *session) error{
	
	sch.monitor.isAtbegining(sch, s)
	//utils.Infof("Here mooo \n\n")

	var pth *path
	alpha := 0.0
	beta := 0.0
	
	// Update leastUnacked value of paths
	s.pathsLock.RLock()
	for _, pthTmp := range s.paths {
		pthTmp.SetLeastUnacked(pthTmp.sentPacketHandler.GetLeastUnacked())
	}
	s.pathsLock.RUnlock()

	// get WindowUpdate frames
	// this call triggers the flow controller to increase the flow control windows, if necessary
	windowUpdateFrames := s.getWindowUpdateFrames(false)
	for _, wuf := range windowUpdateFrames {
		s.packer.QueueControlFrame(wuf, pth)
	}
	
	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	for {
		//coderuntimestart := time.Now().UnixNano() / 1000
		//utils.Infof("\n\n\n")
		// 1. origin: We first check for retransmissions
		issent:=false
		var paths_init []*path
		var firstpath *path
		
		sch.monitor.monitorCurrentSessionState(s)
		hasRetransmission, retransmitHandshakePacket, fromPth := sch.getRetransmission(s)
		// XXX There might still be some stream frames to be retransmitted
		hasStreamRetransmission := s.streamFramer.HasFramesForRetransmission()
		sch.monitor.monitorClear()
		for i, pth := range s.paths{
			if(i != protocol.InitialPathID && pth.SendingAllowed(sch.CWNDFlag)){
				paths_init = append(paths_init, pth)
			}
			// 2. monitor return current state
			sch.monitor.monitorCurrentPathState(pth)
		}
		

		if len(s.paths) <= 1{
			firstpath = s.paths[protocol.InitialPathID]
			if !hasRetransmission && !firstpath.SendingAllowed(sch.CWNDFlag){
				windowUpdateFrames := s.getWindowUpdateFrames(false)
				return sch.ackRemainingPaths(s, windowUpdateFrames)
			}
		}else{
			if len(paths_init) == 0{
				windowUpdateFrames := s.getWindowUpdateFrames(false)
				return sch.ackRemainingPaths(s, windowUpdateFrames)
			}else{
				firstpath = paths_init[0]
			}
		}
		
		// 3. ordering 
		path_order, _ := sch.orderPaths(s)
		// Select the path here
		//s.pathsLock.RLock()
		//pth = sch.selectPathLowLatency(s, hasRetransmission, hasStreamRetransmission, fromPth)			// cx add: select fastest path for retrans
		//s.pathsLock.RUnlock()
		// XXX No more path available, should we have a new QUIC error message?
		// if pth == nil {
		// 	windowUpdateFrames := s.getWindowUpdateFrames(false)
		// 	return sch.ackRemainingPaths(s, windowUpdateFrames)
		// }


		// If we have an handshake packet retransmission, do it directly
		// 3. handle retransmission
		if hasRetransmission && retransmitHandshakePacket != nil {
			
			s.packer.QueueControlFrame(s.paths[path_order[0]].sentPacketHandler.GetStopWaitingFrame(true), s.paths[path_order[0]])
			packet, err := s.packer.PackHandshakeRetransmission(retransmitHandshakePacket, s.paths[path_order[0]])
			if err != nil {
				return err
			}
			if err = s.sendPackedPacket(packet, s.paths[path_order[0]], true); err != nil {
				return err
			}
			continue
		}


		
				
		//4. stream-level statis: how much data will be  sched this turn																	
		numStreams := uint32(len(s.streamsMap.streams))					
		leftoverdataforwriting := 0  																 //total dataforwriting size have not been dispatched
		dataineachstream := make(map[protocol.StreamID] int)	 //dataforwriting size in each stream
		offineachstream := make(map[protocol.StreamID] protocol.ByteCount)	//writeoffset in each stream
		retransBytes := 0
		for j := uint32(0); j < numStreams; j++ {
			// if(j == 1){
			// 	continue			//stream 1 is crypto, tackled separately
			// }
			streamID := s.streamsMap.openStreams[j]
			dataineachstream[streamID] = len(s.streamsMap.streams[streamID].dataForWriting)
			leftoverdataforwriting += dataineachstream[streamID]
			offineachstream[streamID] = s.streamsMap.streams[streamID].writeOffset
		}
		for r := 0 ; r < len(s.streamFramer.retransmissionQueue) ; r ++ {
			retransBytes += len(s.streamFramer.retransmissionQueue[r].Data)
		}
		leftoverdataforwriting += retransBytes
		utils.Infof("[sc]Dataforwriting size :%vB, retransBytes: %v avaliable:%vB", leftoverdataforwriting, retransBytes, sch.monitor.totalcwnd)
	

		// 6. *pro-discard for application layer 
		gap := make(map[uint8] int)					//gap size between paths
		sch.monitor.isBandwidthEnough(sch, leftoverdataforwriting, s)
		sch.monitor.isHighlossrate(sch, s)
		
		// 7.compute needed gap between paths

		//utils.Infof("[sch]------------------COMPUTE&POP--------------------")

		var i int

		for i = 0 ; ( i+1 ) < (len(path_order) - 1) ; i++ {			// -1 minus path 0 
			inx := path_order[i]
			inx1 := path_order[i+1]
			rtt0 := sch.monitor.state_owd[protocol.PathID(inx)]
			rtt1 := sch.monitor.state_owd[protocol.PathID(inx1)]
			//bw0 := sch.monitor.state_bw[protocol.PathID(inx)]
			cw0 := sch.monitor.state_cwnd[protocol.PathID(inx)]			
			
			var computed_needed int

			// // solution 1. bw/alpha
			// computed_needed = int(cw0) + int(((rtt1 - rtt0).Seconds() * float64(bw0)) / alpha) 
			
			// solution 2.

			//sch.Adjustment(s.paths[path_order[i]], s.paths[path_order[i+1]])
			
			if(i == 0 && rtt1 == 0 ){					// if i == 0 gap rtt1 == 0, first path need to send
				computed_needed = leftoverdataforwriting
			//	utils.Infof("[sch]Path %v	gap_needed all leftoverdataforwriting, because RTT is 0", inx)
				//sch.redundancy = protocol.ByteCount(0)
			
			}else{
				
				if(sch.monitor.state_serverinx[protocol.PathID(inx)] < -1000){
					//alpha = float64( -sch.monitor.state_serverinx[protocol.PathID(inx)] / 10.0)
					beta = 0.0
					//alpha = 0.0
					//sch.redundancy = 1312
				}else if(sch.monitor.state_serverinx[protocol.PathID(inx)] > 10000){
					//alpha = float64( -sch.monitor.state_serverinx[protocol.PathID(inx)] / 10.0)
					
					alpha =0.0
					//beta = float64( sch.monitor.state_serverinx[protocol.PathID(inx)] / 10.0)
					sch.redundancy = 0
					
				}else{
					sch.redundancy = 0
					beta = 0.0
					alpha = 0.0
				}
				//utils.Infof("alpha:%v beta:%v",alpha,beta)
				
				n := int( rtt1 / rtt0 )
			
				//inflight :=  int(s.paths[inx].data_insubbuffer) + int(s.paths[inx].sentPacketHandler.GetBytesInflight())
				inflight :=  int(s.paths[inx].data_insubbuffer) 
				for ; (leftoverdataforwriting + inflight) -  computed_needed > 0 && n > 0 ; {
	
					maxLen :=  protocol.ByteCount(cw0)
					computed_needed += int(maxLen)
					n -= 1
					//utils.Infof("[sch]Path %v	computed_needed %v, n %v", inx, computed_needed, n)
				}
	
				computed_needed -= int(alpha)

				if( computed_needed > inflight ){
					computed_needed -= inflight
					if ( computed_needed >= leftoverdataforwriting ){
						computed_needed = leftoverdataforwriting
					}
				}else{
					computed_needed = 0
				}
			}
			
			
			//utils.Infof("[sch]Path %v	computed_needed %v, left_dataforwriting %v", inx, computed_needed, leftoverdataforwriting)

			gap[uint8(inx)] = int(float64(computed_needed) )
			if(gap[uint8(inx)] < 0){
				gap[uint8(inx)] = 0
			}
			//utils.Infof("[sch]produce red:%v",sch.redundancy)
			leftoverdataforwriting -= gap[uint8(inx)]
			
			// // solution 1
			// gap_needed := int(0)
			// utils.Infof("[sch]Path %v	computed_gap: %v, datainsubbuffer: %v, inflight: %v" ,inx, computed_needed,  s.paths[inx].data_insubbuffer, s.paths[inx].sentPacketHandler.GetBytesInflight())
			// if computed_needed > leftoverdataforwriting{
			// 	gap_needed = leftoverdataforwriting
			// }else{
			// 	gap_needed = computed_needed
			// }

			// if gap_needed + int(s.paths[inx].data_insubbuffer) + int(s.paths[inx].sentPacketHandler.GetBytesInflight()) > computed_needed{
			// 	utils.Infof("[sch]gap_needed should be reduced, because inflight and datainsubbuffer")
			// 	gap_needed = computed_needed -  int(s.paths[inx].data_insubbuffer) - int(s.paths[inx].sentPacketHandler.GetBytesInflight())
			// } 
			// if(i == 0 && rtt1 == 0){					// if i == 0 gap rtt1 == 0, first path need to send
			// 	gap_needed = leftoverdataforwriting
			// 	utils.Infof("[sch]Path %v	gap_needed all leftoverdataforwriting, because RTT is 0")
			// }
			// if(gap_needed > 0 && leftoverdataforwriting - gap_needed > 0 ){
			// 	leftoverdataforwriting -= gap_needed
			// }else if(gap_needed > 0 && leftoverdataforwriting - gap_needed <= 0 ){
			// 	gap_needed = leftoverdataforwriting
			// 	leftoverdataforwriting = 0
			// }

			// utils.Infof("[sch]Path %v	gap_needed: %v, leftoverdataforwrting: %v", inx, gap_needed, leftoverdataforwriting)
			// gap[uint8(inx)] = gap_needed
			// needed_sum += gap_needed
			
			sch.assign_streamoff(s.paths[inx], s, dataineachstream, offineachstream, gap)
			s.streamFramer.maybePopData(protocol.ByteCount(gap[uint8(inx)]), s.paths[inx], sch.redundancy, sch)
			if(i == 0 && rtt1 == 0 ){					// if i == 0 gap rtt1 == 0, first path need to send
				break
			}
		}

		//snd, _ := s.flowControlManager.SendWindowSize(protocol.StreamID(3))
		//utils.Infof("[sch]send window:%v",snd)	
		if(len(path_order) >= 2){
			i = (len(path_order) - 2)
		}else{
			i = 0
		}

		if(path_order[i] != 0){
			
			//utils.Infof("[sch]----------lastorder path:%v -----------", path_order[i])
			/////////////////////////////////////////////////////////////////////
			// if(s.paths[path_order[i]].rttStats.SmoothedRTT() == 0){
			// 	sch.redundancy = protocol.ByteCount(1358)
			// 	utils.Infof("path %v make reduncancy 1000bytes", path_order[i])
			// }else{
			// 	sch.redundancy = protocol.ByteCount(0)
			// }
		
			// lenredundancy := len(sch.redundancy_data)
			// utils.Infof("[sch]		redundancy: %v, red len: %v, start: %v, end: %v", sch.redundancy, lenredundancy, sch.redundancy_stream_off_start, sch.redundancy_stream_off_end)
			// if(len(sch.redundancy_data) > 0){
			// 	if(s.paths[path_order[i]].stream_off[protocol.StreamID(3)] == nil){
			// 		s.paths[path_order[i]].stream_off[protocol.StreamID(3)] = utils.NewByteIntervalList()
			// 		s.paths[path_order[i]].stream_off[protocol.StreamID(3)].PushFront(utils.ByteInterval{Start:  sch.redundancy_stream_off_start , End:  sch.redundancy_stream_off_end})
			// 		utils.Infof("[sch]		red from nil stream_off updated %v ", s.paths[path_order[i]].stream_off[protocol.StreamID(3)].Front().Value)
			// 		s.paths[path_order[i]].data_insubbuffer += protocol.ByteCount(lenredundancy)
			// 		s.paths[path_order[i]].sub_buffer[protocol.StreamID(3)] = append(s.paths[path_order[i]].sub_buffer[protocol.StreamID(3)], sch.redundancy_data...)
					
			// 	}else{
			// 		//utils.Infof("[sch]		red last %v", s.paths[path_order[i]].stream_off[protocol.StreamID(3)].Back().Value)
			// 		last_off := s.paths[path_order[i]].stream_off[protocol.StreamID(3)].Back()
			// 		if last_off.Value.End ==  sch.redundancy_stream_off_start {				// same, just expand last_off
			// 			s.paths[path_order[i]].stream_off[protocol.StreamID(3)].Back().Value.End += protocol.ByteCount(lenredundancy)
			// 			utils.Infof("[sch]		red stream_off updated, cnt:%v, front:%v, back:%v", s.paths[path_order[i]].stream_off[protocol.StreamID(3)].Len(), s.paths[path_order[i]].stream_off[protocol.StreamID(3)].Front(), s.paths[path_order[i]].stream_off[protocol.StreamID(3)].Back())
			// 			s.paths[path_order[i]].data_insubbuffer += protocol.ByteCount(lenredundancy)
			// 			s.paths[path_order[i]].sub_buffer[protocol.StreamID(3)] = append(s.paths[path_order[i]].sub_buffer[protocol.StreamID(3)], sch.redundancy_data...)			
			// 		}else if last_off.Value.End < sch.redundancy_stream_off_start{
			// 			newoff := utils.ByteInterval{Start:  sch.redundancy_stream_off_start , End:  sch.redundancy_stream_off_end}
			// 			s.paths[path_order[i]].stream_off[protocol.StreamID(3)].PushBack(newoff)	
			// 			//pth.stream_off[s.streamID] = append(pth.stream_off[s.streamID], newoff)
			// 			utils.Infof("[sch]		 red stream_off updated, cnt:%v, front:%v ",s.paths[path_order[i]].stream_off[protocol.StreamID(3)].Len(), s.paths[path_order[i]].stream_off[protocol.StreamID(3)].Front())
			// 			s.paths[path_order[i]].data_insubbuffer += protocol.ByteCount(lenredundancy)
			// 			s.paths[path_order[i]].sub_buffer[protocol.StreamID(3)] = append(s.paths[path_order[i]].sub_buffer[protocol.StreamID(3)], sch.redundancy_data...)
				
			// 		}else{
			// 			utils.Infof("[sch]		red error!")
			// 		}
			// 	}
			// }
			/////////////////////////////////////////////////////////////////////
			
			
			bw_last := int((sch.monitor.state_cwnd[protocol.PathID(path_order[i])]) )
			
			//utils.Infof("[sch]lastorder path computed_gap : %v datainsubbuffer : %v", bw_last, int( s.paths[protocol.PathID(path_order[i])].data_insubbuffer ))
			inflight :=  int(s.paths[protocol.PathID(path_order[i])].data_insubbuffer) 
			//inflight := int(s.paths[protocol.PathID(path_order[i])].data_insubbuffer) + int(s.paths[protocol.PathID(path_order[i])].sentPacketHandler.GetBytesInflight())

			if( bw_last > inflight ){
				gap[uint8(path_order[i])] = bw_last - inflight - int(beta)
				if ( gap[uint8(path_order[i])] >= leftoverdataforwriting ){
					gap[uint8(path_order[i])] = leftoverdataforwriting
				}
			}else{
				gap[uint8(path_order[i])] = 0
			}
			if( gap[uint8(path_order[i])] < 0 ){
				gap[uint8(path_order[i])] = 0
			}

			leftoverdataforwriting -= gap[uint8(path_order[i])]
			//utils.Infof("[sch]lastorder path : %v, need_gap: %v, reside: %v, datainsubbufer: %v",  path_order[i], gap[uint8(path_order[i])], leftoverdataforwriting,  s.paths[path_order[i]].data_insubbuffer)
			
			sch.assign_streamoff(s.paths[path_order[i]], s , dataineachstream, offineachstream, gap)
			s.streamFramer.maybePopData(protocol.ByteCount(gap[uint8(path_order[i])]), s.paths[path_order[i]], sch.redundancy, sch)
		
		}else{
			gap[uint8(path_order[i])] = 0
			//utils.Infof("[sch]lastorder path : %v, need_gap:%v, reside: %v, datainsubbufer: %v",  path_order[i], gap[uint8(path_order[i])], leftoverdataforwriting,  s.paths[path_order[i]].data_insubbuffer)
			sch.assign_streamoff(s.paths[path_order[i]], s , dataineachstream, offineachstream, gap)
			s.streamFramer.maybePopData(protocol.ByteCount(gap[uint8(path_order[i])]), s.paths[path_order[i]], sch.redundancy, sch)

		}


		// 4.  enQueue other controll frames
		// Also add CLOSE_PATH frames, if any
			
		for cpf := s.streamFramer.PopClosePathFrame(); cpf != nil; cpf = s.streamFramer.PopClosePathFrame() {
			s.packer.QueueControlFrame(cpf, pth)
		}

		// Also add ADD ADDRESS frames, if any
		for aaf := s.streamFramer.PopAddAddressFrame(); aaf != nil; aaf = s.streamFramer.PopAddAddressFrame() {
			s.packer.QueueControlFrame(aaf, pth)
			//utils.Infof("[sch]:ADD_ADDRESS:%v, ctrlqueue:%v",aaf,len(s.packer.controlFrames))
		}

		// Also add PATHS frames, if any
		for pf := s.streamFramer.PopPathsFrame(); pf != nil; pf = s.streamFramer.PopPathsFrame() {
			s.packer.QueueControlFrame(pf, pth)
		}
		
		//utils.Infof("[sch]end leftoverdataforwriting : %v", leftoverdataforwriting)  


		
		//utils.Infof("----------------------PACK--------------------------------")
		for _, pathID := range path_order{
			if(pathID == protocol.InitialPathID && len(path_order) > 1) {			// only path 0 just take path 0
				continue
			}
			
			pth := s.paths[protocol.PathID(pathID)]
			if !pth.SendingAllowed(sch.CWNDFlag){
				continue					
			}
			//pth := s.paths[protocol.PathID(0)]
			//utils.Infof("\n")
			//utils.Infof("[sch]Path: %v", pathID)
			// XXX Some automatic ACK generation should be done someway.
			// 5.1 add ack and sw
			var ack *wire.AckFrame
			ack = pth.GetAckFrame()
			if ack != nil {
				s.packer.QueueControlFrame(ack, pth)
				//utils.Infof("[sendpacketmooo]: ACK %v", ack)
			}
			if ack != nil || hasStreamRetransmission {
				swf := pth.sentPacketHandler.GetStopWaitingFrame(hasStreamRetransmission)
				if swf != nil {
					s.packer.QueueControlFrame(swf, pth)
					//utils.Infof("[sendpacketmooo]: SWF %v", swf)
				}
			}

			// 5.1 new cx fix : ack return via faster path
			// var ack *wire.AckFrame
			// for _, pathIDtmp := range path_order{
			// 	pth_tmp := s.paths[protocol.PathID(pathIDtmp)]
			// 	ack = pth_tmp.GetAckFrame()
			// 	if ack != nil {
			// 		s.packer.QueueControlFrame(ack, pth_tmp)
			// 		//utils.Infof("[sendpacketmooo]: ACK %v", ack)
			// 	}
			// 	if ack != nil || hasStreamRetransmission {
			// 		swf := pth.sentPacketHandler.GetStopWaitingFrame(hasStreamRetransmission)
			// 		if swf != nil {
			// 			s.packer.QueueControlFrame(swf, pth_tmp)
			// 			//utils.Infof("[sendpacketmooo]: SWF %v", swf)
			// 		}
			// 	}
			// }
			
			// 5.2 performpacketsending
			pkt, sent, err := sch.performPacketSendingMOOO(s, windowUpdateFrames, pth, gap)
			//pkt, sent, err := sch.performPacketSending(s, windowUpdateFrames, pth)
			if sent{
				issent = true
				//coderuntimeend := time.Now().UnixNano() /1000
				//sch.totalruntime += coderuntimeend - coderuntimestart
				//sch.totalpacketnum += 1
				//utils.Infof("totalruntime:%v, num:%v",sch.totalruntime, sch.totalpacketnum)
			}
			if err != nil {
				return err
			}
			windowUpdateFrames = nil
			//cx add 1214: from !sent to just one send is ok!
			//utils.Infof("[sch]sent?%v", sent)
			// if sent == true {
			// 	// Prevent sending empty packets
			// 	sentFlag = true
			// }
			// if !sent{
			// 	return sch.ackRemainingPaths(s, windowUpdateFrames)
			// }//*/
			// Duplicate traffic when it was sent on an unknown performing path
			// FIXME adapt for new paths coming during the connection
			if pth.rttStats.SmoothedRTT() == 0 {
				currentQuota := sch.quotas[pth.pathID]
				utils.Infof("[sch]duplicated!")
				// Was the packet duplicated on all potential paths?
			duplicateLoop:
				for pathID, tmpPth := range s.paths {
					
					if pathID == protocol.InitialPathID || pathID == pth.pathID {
						continue
					}
					if sch.quotas[pathID] < currentQuota && tmpPth.sentPacketHandler.SendingAllowed(sch.CWNDFlag) {
						// Duplicate it
						pth.sentPacketHandler.DuplicatePacket(pkt)
						break duplicateLoop
					}
				}


			}
			
		}
		s.packer.lastdataforwritinglen = 0
		// if sentFlag == true{
		// //if !sent{
		// 	return sch.ackRemainingPaths(s, windowUpdateFrames)
		// }//*/
		/* cx add for debug:origin code
			// XXX Some automatic ACK generation should be done someway
			var ack *wire.AckFrame

			ack = pth.GetAckFrame()
			if ack != nil {
				s.packer.QueueControlFrame(ack, pth)
			}
			if ack != nil || hasStreamRetransmission {
				swf := pth.sentPacketHandler.GetStopWaitingFrame(hasStreamRetransmission)
				if swf != nil {
					s.packer.QueueControlFrame(swf, pth)
				}
			}
			pkt, sent, err := sch.performPacketSending(s, windowUpdateFrames, pth)
		if err != nil {
			return err
		}
		windowUpdateFrames = nil
		if !sent {
			// Prevent sending empty packets
			return sch.ackRemainingPaths(s, windowUpdateFrames)
		}

		// Duplicate traffic when it was sent on an unknown performing path
		// FIXME adapt for new paths coming during the connection
		if pth.rttStats.SmoothedRTT() == 0 {
			
			currentQuota := sch.quotas[pth.pathID]
			// Was the packet duplicated on all potential paths?
		duplicateLoop:
			for pathID, tmpPth := range s.paths {
				if pathID == protocol.InitialPathID || pathID == pth.pathID {
					continue
				}
				if sch.quotas[pathID] < currentQuota && tmpPth.sentPacketHandler.SendingAllowed() {
					// Duplicate it
					utils.Infof("[sch]duplicated!")
					pth.sentPacketHandler.DuplicatePacket(pkt)
					break duplicateLoop
				}
			}
		}
*/
			// And try pinging on potentially failed paths
			if fromPth != nil && fromPth.potentiallyFailed.Get() {
				utils.Infof("potential failed!")
				err := s.sendPing(fromPth)
				if err != nil {
					return err
				}
			}
			windowUpdateFrames = nil
			if !issent{
				return sch.ackRemainingPaths(s, windowUpdateFrames)
			}//*/
	}	
}

// func(sch *scheduler) make_redundancy(thispth *path, lastpth *path, start protocol.ByteCount, end protocol.ByteCount, data []byte){
// 	//start, end has known
// 	//get corresponding subbuffer from last path, and adding stream_off to this path
// 	lendata := end - start 
// 	// if(lendata > protocol.ByteCount(len(lastpth.sub_buffer[protocol.StreamID(3)]))){
// 	// 	lendata = protocol.ByteCount(len(lastpth.sub_buffer[protocol.StreamID(3)]))
// 	// 	start = end - lendata
// 	// }
// 	utils.Infof("[sch]	thispth:%v, lastpth:%v, from: %v, to: %v", thispth.pathID, lastpth.pathID, len(lastpth.sub_buffer[protocol.StreamID(3)]) - int(lendata), len(lastpth.sub_buffer[protocol.StreamID(3)]))
// 	if(start == end){
// 		utils.Infof("[sch]	redun lendata zero, will return!")
// 		return 
// 	}

// 	//data := lastpth.sub_buffer[protocol.StreamID(3)][len(lastpth.sub_buffer[protocol.StreamID(3)]) - int(lendata) : len(lastpth.sub_buffer[protocol.StreamID(3)])]
// 	// append data to this path's sub_buffer
// 	// // update stream_off: start, end
// 	utils.Infof("[sch]	redun lendata %v", len(data))
// 	if(thispth.stream_off[protocol.StreamID(3)] == nil){
// 		thispth.stream_off[protocol.StreamID(3)] = utils.NewByteIntervalList()
// 		thispth.stream_off[protocol.StreamID(3)].PushFront(utils.ByteInterval{Start: start, End:  end})
// 		//data := lastpth.sub_buffer[protocol.StreamID(3)][len(lastpth.sub_buffer[protocol.StreamID(3)]) - int(lendata) : len(lastpth.sub_buffer[protocol.StreamID(3)])]
// 		thispth.sub_buffer[protocol.StreamID(3)] = append(thispth.sub_buffer[protocol.StreamID(3)],data ...)
// 		thispth.data_insubbuffer += protocol.ByteCount(len(data))
// 		utils.Infof("[sch]		make redundancy from nil to stream_off updated back:%v len sub_buffer: %v", thispth.stream_off[protocol.StreamID(3)].Back().Value, len(thispth.sub_buffer[protocol.StreamID(3)]))
// 	}else{
// 		var now *utils.ByteIntervalElement
// 		var sub_buffer_inx protocol.ByteCount
// 		for now = thispth.stream_off[protocol.StreamID(3)].Front(); now != nil; now = now.Next() {
// 			len_now := now.Value.End - now.Value.Start
// 			if(start > now.Value.End){
// 				sub_buffer_inx += len_now
// 				continue
// 			}
// 			if(start <= now.Value.Start && end <= now.Value.End){
// 				prev := now.Prev()
// 				if(prev == nil || start > prev.Value.End){
// 					var newmergesub_buffer []byte
// 					lencutdata := int(now.Value.Start - start)
// 					thispth.stream_off[protocol.StreamID(3)].InsertBefore(utils.ByteInterval{Start: start, End: now.Value.End}, now)
// 					utils.Infof("[sch]		 make redundancy stream_off updated, cnt:%v, from %v to %v ",thispth.stream_off[protocol.StreamID(3)].Len(),start, now.Value.End)
// 					thispth.stream_off[protocol.StreamID(3)].Remove(now)
					
// 					//data := lastpth.sub_buffer[protocol.StreamID(3)][len(lastpth.sub_buffer[protocol.StreamID(3)]) - int(lendata) : len(lastpth.sub_buffer[protocol.StreamID(3)])]
// 					before_part := thispth.sub_buffer[protocol.StreamID(3)][:sub_buffer_inx]
// 					behind_part := thispth.sub_buffer[protocol.StreamID(3)][sub_buffer_inx:]
// 					newmergesub_buffer = append(newmergesub_buffer, before_part...)
// 					newmergesub_buffer = append(newmergesub_buffer, data[:lencutdata]...)
// 					newmergesub_buffer = append(newmergesub_buffer, behind_part...)
// 					thispth.sub_buffer[protocol.StreamID(3)] = newmergesub_buffer
// 					thispth.data_insubbuffer += protocol.ByteCount(lencutdata)
// 					sub_buffer_inx += len_now
// 					utils.Infof("[sch]		make redundancy from nil to stream_off updated back:%v len sub_buffer: %v", thispth.stream_off[protocol.StreamID(3)].Back().Value, len(thispth.sub_buffer[protocol.StreamID(3)]))
// 				}else{
// 					thispth.stream_off[protocol.StreamID(3)].InsertBefore(utils.ByteInterval{Start: prev.Value.Start, End: now.Value.End}, prev)
// 					utils.Infof("[sch]		 make redundancy stream_off updated, cnt:%v, from %v to %v ",thispth.stream_off[protocol.StreamID(3)].Len(),prev.Value.Start, now.Value.End)
// 					thispth.stream_off[protocol.StreamID(3)].Remove(now)
// 					thispth.stream_off[protocol.StreamID(3)].Remove(prev)
// 				}
// 				break
// 			}else if(start <= now.Value.Start && end >= now.Value.End){
// 				prev := now.Prev()
// 				if(prev == nil || start > prev.Value.End){
// 					thispth.stream_off[protocol.StreamID(3)].InsertBefore(utils.ByteInterval{Start: start, End: end}, now)
// 					utils.Infof("[sch]		 make redundancy stream_off updated, cnt:%v, from %v to %v ",thispth.stream_off[protocol.StreamID(3)].Len(),start, end)
// 					thispth.stream_off[protocol.StreamID(3)].Remove(now)
// 				}else{
// 					thispth.stream_off[protocol.StreamID(3)].InsertBefore(utils.ByteInterval{Start: prev.Value.Start, End: end}, prev)
// 					utils.Infof("[sch]		 make redundancy stream_off updated, cnt:%v, from %v to %v ",thispth.stream_off[protocol.StreamID(3)].Len(),prev.Value.Start, end)
// 					thispth.stream_off[protocol.StreamID(3)].Remove(now)
// 					thispth.stream_off[protocol.StreamID(3)].Remove(prev)
// 				}
// 				break
// 			}else if(start >= now.Value.Start && end >= now.Value.End){
// 				thispth.stream_off[protocol.StreamID(3)].InsertBefore(utils.ByteInterval{Start: now.Value.Start, End: end}, now)
// 				utils.Infof("[sch]		 make redundancy stream_off updated, cnt:%v, from %v to %v ",thispth.stream_off[protocol.StreamID(3)].Len(), now.Value.Start, end)
// 				thispth.stream_off[protocol.StreamID(3)].Remove(now)
// 				break
// 			}
// 		}
// 		if(now == nil){
// 			// push back
// 			newoff := utils.ByteInterval{Start: start, End:  end}
// 			utils.Infof("[sch]		 make new redundancy stream_off , cnt:%v, from %v to %v ",thispth.stream_off[protocol.StreamID(3)].Len(), start, end)
// 			thispth.stream_off[protocol.StreamID(3)].PushBack(newoff)
// 		}
		
		
// 		// last_off := thispth.stream_off[protocol.StreamID(3)].Back()
// 		// utils.Infof("[sch]	last_off end %v, start  %v", last_off.Value.End, start)
// 		// if last_off.Value.End == start{				// same, just expand last_off
// 		// 	thispth.stream_off[protocol.StreamID(3)].Back().Value.End = end
// 		// 	utils.Infof("[sch]		make redundancy stream_off updated, cnt:%v, back:%v", thispth.stream_off[protocol.StreamID(3)].Len(), thispth.stream_off[protocol.StreamID(3)].Back().Value)
// 		// }else if last_off.Value.End < start {
// 		// 	newoff := utils.ByteInterval{Start: start, End:  end}
// 		// 	thispth.stream_off[protocol.StreamID(3)].PushBack(newoff)	
// 		// 	//pth.stream_off[s.streamID] = append(pth.stream_off[s.streamID], newoff)
// 		// 	utils.Infof("[sch]		 make redundancy stream_off updated, cnt:%v, back:%v ",thispth.stream_off[protocol.StreamID(3)].Len(), thispth.stream_off[protocol.StreamID(3)].Back().Value)
// 		// }else{
// 		// 	utils.Infof("[sch]		repeat redundancy, last off %v, start:%v, cnt: %v, error! return", last_off.Value, start, thispth.stream_off[protocol.StreamID(3)].Len())
// 		// 	return
// 		// }
// 	}


// 	// thispth.sub_buffer[protocol.StreamID(3)] = append(thispth.sub_buffer[protocol.StreamID(3)],data ...)
// 	// thispth.data_insubbuffer += protocol.ByteCount(len(data))
// 	utils.Infof("[sch]		have made redundancy")

// }

func(sch *scheduler) assign_streamoff(pth *path, s *session, dataineachstream map[protocol.StreamID] int, offineachstream map[protocol.StreamID] protocol.ByteCount, gap map[uint8] int){
	numStreams := uint32(len(s.streamsMap.streams))
	utils.Infof("[sch]	Writeoffset of each stream: 0x%x", offineachstream)
	utils.Infof("[sch]	Path %v gap size %v", pth.pathID, gap[uint8(pth.pathID)])
	for j := uint32(0); j < numStreams; j++ {
		// if(j == 1){
		// 	continue			//stream 1 is crypto, tackled separately
		// }
		streamID := s.streamsMap.openStreams[j]
		utils.Infof("[sch]		Stream %v dataforwriting size : %v", streamID, dataineachstream[streamID])
		//str := s.streamsMap.streams[streamID]
		if(dataineachstream[streamID] == 0){
			continue
		}
		if(gap[uint8(pth.pathID)] <= 0){
			break
		}
		if(dataineachstream[streamID] < gap[uint8(pth.pathID)]){
			if(pth.assigned_stream_off[streamID] == nil){
				pth.assigned_stream_off[streamID] = utils.NewByteIntervalList()	
				pth.assigned_stream_off[streamID].PushFront(utils.ByteInterval{Start:  offineachstream[streamID], End: offineachstream[streamID] + protocol.ByteCount(dataineachstream[streamID])})
				utils.Infof("[sch]		Path %v stream %v new assigned_stream_off", pth.pathID, streamID)
			}else{
				last_off := pth.assigned_stream_off[streamID].Back()
				if last_off.Value.End == offineachstream[streamID] {
					utils.Infof("[sch]		assigned merge %v", pth.assigned_stream_off[streamID].Back())
					pth.assigned_stream_off[streamID].Back().Value.End += protocol.ByteCount(dataineachstream[streamID])
				}else{
					newoff := utils.ByteInterval{Start: offineachstream[streamID] , End:  offineachstream[streamID] + protocol.ByteCount(dataineachstream[streamID])}
					
					pth.assigned_stream_off[streamID].PushBack(newoff)
					utils.Infof("[sch]		assigned new %v", pth.assigned_stream_off[streamID].Back())
				}

			}
			utils.Infof("[sch]		path %v stream %v append to assigned_stream_off, size: %v, from 0x%x, to :0x%x", pth.pathID, streamID, dataineachstream[streamID], offineachstream[streamID], pth.assigned_stream_off[streamID].Back().Value.End)

			offineachstream[streamID] += protocol.ByteCount(dataineachstream[streamID])
			dataineachstream[streamID] = 0 
		}else{
			if(pth.assigned_stream_off[streamID] == nil){
				pth.assigned_stream_off[streamID] = utils.NewByteIntervalList()	
				pth.assigned_stream_off[streamID].PushFront(utils.ByteInterval{Start:  offineachstream[streamID] , End: offineachstream[streamID] + protocol.ByteCount(gap[uint8(pth.pathID)])})
				utils.Infof("[sch]		path %v stream %v new assigned_stream_off", pth.pathID, streamID)
			}else{
				last_off := pth.assigned_stream_off[streamID].Back()
				if last_off.Value.End == offineachstream[streamID]{
					pth.assigned_stream_off[streamID].Back().Value.End += protocol.ByteCount(gap[uint8(pth.pathID)])
					utils.Infof("[sch]		assigned merge %v", pth.assigned_stream_off[streamID].Back())
				}else{
					newoff := utils.ByteInterval{Start:  offineachstream[streamID] , End: offineachstream[streamID] + protocol.ByteCount(gap[uint8(pth.pathID)])}
					
					pth.assigned_stream_off[streamID].PushBack(newoff)	
					utils.Infof("[sch]		assigned new %v", pth.assigned_stream_off[streamID].Back())
				}
			}
			utils.Infof("[sch]		path %v stream %v append to assigned_stream_off, size: %v, from 0x%x, to 0x%x", pth.pathID, streamID, protocol.ByteCount(gap[uint8(pth.pathID)]), offineachstream[streamID], pth.assigned_stream_off[streamID].Back().Value.End)
			offineachstream[streamID] += protocol.ByteCount(gap[uint8(pth.pathID)])
			dataineachstream[streamID] -= gap[uint8(pth.pathID)]
		}
		
		utils.Infof("[sch]		path %v stream %v assigned_stream_off  cnt:%v, back: %v", pth.pathID, streamID, pth.assigned_stream_off[streamID].Len(), pth.assigned_stream_off[streamID].Back())
	}
}

func (sch *scheduler) sendPacketRedundancy(s *session) error {
	var pth *path
	//utils.Infof("Here redundancy \n\n")
	// Update leastUnacked value of paths
	s.pathsLock.RLock()
	for _, pthTmp := range s.paths {
		pthTmp.SetLeastUnacked(pthTmp.sentPacketHandler.GetLeastUnacked())
	}
	s.pathsLock.RUnlock()

	// get WindowUpdate frames
	// this call triggers the flow controller to increase the flow control windows, if necessary
	windowUpdateFrames := s.getWindowUpdateFrames(false)
	for _, wuf := range windowUpdateFrames {
		s.packer.QueueControlFrame(wuf, pth)
	}

	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	for {
		
		issent:=false
		var firstpath *path
		var paths []*path
		// We first check for retransmissions
		hasRetransmission, retransmitHandshakePacket, fromPth := sch.getRetransmission(s)
		// XXX There might still be some stream frames to be retransmitted
		hasStreamRetransmission := s.streamFramer.HasFramesForRetransmission()
		sch.monitor.monitorClear()
		// Select the path here
		//s.pathsLock.RLock()
		// cx add:get all availiable paths
		sch.monitor.monitorCurrentSessionState(s)
		firstpath = sch.selectPathLowLatency(s, hasRetransmission, hasStreamRetransmission, fromPth)			// cx tent to select path with minrtt as first path
		//firstpath = sch.selectPathLowLatency(s, hasRetransmission, hasStreamRetransmission, fromPth)	
		if(firstpath != nil){
			paths = append(paths, firstpath)
		}
		for i,pth := range s.paths{
			if( i != protocol.InitialPathID && pth.SendingAllowed(sch.CWNDFlag) && ((firstpath != nil && i != firstpath.pathID ) || firstpath == nil ) ){
				paths = append(paths, pth)
			}
			sch.monitor.monitorCurrentPathState(pth)
		}
		
		//sch.monitor.isHighlossrate(sch, s)
		

		if len(s.paths) == 1{
			firstpath = s.paths[protocol.InitialPathID]
			paths = append(paths, firstpath)
		}else{
			if len(paths) == 0{
				windowUpdateFrames := s.getWindowUpdateFrames(false)
				return sch.ackRemainingPaths(s, windowUpdateFrames)
			}else{
				firstpath = paths[0]
			}
		}
		//utils.Infof("[sch]avail paths:%v",paths)
		//pth = sch.selectPath(s, hasRetransmission, hasStreamRetransmission, fromPth)
		//s.pathsLock.RUnlock()

		// If we have an handshake packet retransmission, do it directly
		if hasRetransmission && retransmitHandshakePacket != nil {
			s.packer.QueueControlFrame(firstpath.sentPacketHandler.GetStopWaitingFrame(true), firstpath)
			packet, err := s.packer.PackHandshakeRetransmission(retransmitHandshakePacket, firstpath)
			if err != nil {
				return err
			}
			if err = s.sendPackedPacket(packet, firstpath, true); err != nil {
				return err
			}
			continue
		}

		
		// Also add CLOSE_PATH frames, if any
		for cpf := s.streamFramer.PopClosePathFrame(); cpf != nil; cpf = s.streamFramer.PopClosePathFrame() {
			s.packer.QueueControlFrame(cpf, pth)
		}

		// Also add ADD ADDRESS frames, if any
		for aaf := s.streamFramer.PopAddAddressFrame(); aaf != nil; aaf = s.streamFramer.PopAddAddressFrame() {
			s.packer.QueueControlFrame(aaf, pth)
		}

		// Also add PATHS frames, if any
		for pf := s.streamFramer.PopPathsFrame(); pf != nil; pf = s.streamFramer.PopPathsFrame() {
			s.packer.QueueControlFrame(pf, pth)
		}
		/////////////////
		
		for i , pth := range paths{
			// XXX Some automatic ACK generation should be done someway
			//utils.Infof("[scheduler]now path:%v",pth.pathID)
			var ack *wire.AckFrame

			ack = pth.GetAckFrame()
			if ack != nil {
			s.packer.QueueControlFrame(ack, pth)
			}
			if ack != nil || hasStreamRetransmission {
				swf := pth.sentPacketHandler.GetStopWaitingFrame(hasStreamRetransmission)
				if swf != nil {
					s.packer.QueueControlFrame(swf, pth)
				}
			}
			if i == 0{
				_, sent, err := sch.performPacketSendingRedundancy(s, windowUpdateFrames, pth, true)
				if err != nil {
					return err
				}
				//utils.Infof("[sch]path:%v sent:%v",pth.pathID,sent)
				if sent{
					issent = true
				}
			}else{
				_, sent, err := sch.performPacketSendingRedundancy(s, windowUpdateFrames, pth, false)
				//utils.Infof("[sch]path:%v sent:%v",pth.pathID,sent)
				if err != nil {
					return err
				}
				if sent{
					issent = true
				}
			}
				
			


			// Duplicate traffic when it was sent on an unknown performing path
			// FIXME adapt for new paths coming during the connection
			// if pth.rttStats.SmoothedRTT() == 0 {
				
			// 	currentQuota := sch.quotas[pth.pathID]
			// 	// Was the packet duplicated on all potential paths?
			// duplicateLoop:
			// 	for pathID, tmpPth := range s.paths {
			// 		if pathID == protocol.InitialPathID || pathID == pth.pathID {
			// 			continue
			// 		}
			// 		if sch.quotas[pathID] < currentQuota && tmpPth.sentPacketHandler.SendingAllowed() {
			// 			// Duplicate it
			// 			utils.Infof("[sch]duplicated!")
			// 			pth.sentPacketHandler.DuplicatePacket(pkt)
			// 			break duplicateLoop
			// 		}
			// 	}
			// }

			// And try pinging on potentially failed paths
			if fromPth != nil && fromPth.potentiallyFailed.Get() {
				err := s.sendPing(fromPth)
				if err != nil {
					return err
				}
			}
		}
		windowUpdateFrames = nil
		//utils.Infof("[ori sendpacketred]:issent?%v", issent)
		if !issent {
			// Prevent sending empty packets
			return sch.ackRemainingPaths(s, windowUpdateFrames)
		}

	}
}
func (sch *scheduler) sendPacketRDDT(s *session) error {
	var pth *path
	//utils.Infof("Here redundancy \n\n")
	// Update leastUnacked value of paths
	s.pathsLock.RLock()
	for _, pthTmp := range s.paths {
		pthTmp.SetLeastUnacked(pthTmp.sentPacketHandler.GetLeastUnacked())
	}
	s.pathsLock.RUnlock()
	
	// get WindowUpdate frames
	// this call triggers the flow controller to increase the flow control windows, if necessary
	windowUpdateFrames := s.getWindowUpdateFrames(false)
	for _, wuf := range windowUpdateFrames {
		s.packer.QueueControlFrame(wuf, pth)
	}

	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	for {
		
		issent:=false
		var firstpath *path
		var paths []*path
		// We first check for retransmissions
		sch.monitor.monitorClear()
		sch.monitor.monitorCurrentSessionState(s)
		hasRetransmission, retransmitHandshakePacket, fromPth := sch.getRetransmission(s)
		// XXX There might still be some stream frames to be retransmitted
		hasStreamRetransmission := s.streamFramer.HasFramesForRetransmission()

		// Select the path here
		//s.pathsLock.RLock()
		// cx add:get all availiable paths

		firstpath = sch.selectPathLowLatency(s, hasRetransmission, hasStreamRetransmission, fromPth)			// cx tent to select path with minrtt as first path
		//firstpath = sch.selectPathLowLatency(s, hasRetransmission, hasStreamRetransmission, fromPth)	
		if(firstpath != nil){
			paths = append(paths, firstpath)
		}
		for i,pth := range s.paths{
			if( i != protocol.InitialPathID && pth.SendingAllowed(sch.CWNDFlag) && ((firstpath != nil && i != firstpath.pathID ) || firstpath == nil ) ){
				paths = append(paths, pth)
			}
			sch.monitor.monitorCurrentPathState(pth)
		}
		
		//sch.monitor.isHighlossrate(sch, s)
		

		if len(s.paths) == 1{
			firstpath = s.paths[protocol.InitialPathID]
			paths = append(paths, firstpath)
		}else{
			if len(paths) == 0{
				windowUpdateFrames := s.getWindowUpdateFrames(false)
				return sch.ackRemainingPaths(s, windowUpdateFrames)
			}else{
				firstpath = paths[0]
			}
		}
		//utils.Infof("[sch]avail paths:%v",paths)
		//pth = sch.selectPath(s, hasRetransmission, hasStreamRetransmission, fromPth)
		//s.pathsLock.RUnlock()

		// If we have an handshake packet retransmission, do it directly
		if hasRetransmission && retransmitHandshakePacket != nil {
			s.packer.QueueControlFrame(firstpath.sentPacketHandler.GetStopWaitingFrame(true), firstpath)
			packet, err := s.packer.PackHandshakeRetransmission(retransmitHandshakePacket, firstpath)
			if err != nil {
				return err
			}
			if err = s.sendPackedPacket(packet, firstpath, true); err != nil {
				return err
			}
			continue
		}

		
		// Also add CLOSE_PATH frames, if any
		for cpf := s.streamFramer.PopClosePathFrame(); cpf != nil; cpf = s.streamFramer.PopClosePathFrame() {
			s.packer.QueueControlFrame(cpf, pth)
		}

		// Also add ADD ADDRESS frames, if any
		for aaf := s.streamFramer.PopAddAddressFrame(); aaf != nil; aaf = s.streamFramer.PopAddAddressFrame() {
			s.packer.QueueControlFrame(aaf, pth)
		}

		// Also add PATHS frames, if any
		for pf := s.streamFramer.PopPathsFrame(); pf != nil; pf = s.streamFramer.PopPathsFrame() {
			s.packer.QueueControlFrame(pf, pth)
		}
		/////////////////
		
		for i , pth := range paths{
			// XXX Some automatic ACK generation should be done someway
			//utils.Infof("[scheduler]now path:%v",pth.pathID)
			var ack *wire.AckFrame

			ack = pth.GetAckFrame()
			if ack != nil {
			s.packer.QueueControlFrame(ack, pth)
			}
			if ack != nil || hasStreamRetransmission {
				swf := pth.sentPacketHandler.GetStopWaitingFrame(hasStreamRetransmission)
				if swf != nil {
					s.packer.QueueControlFrame(swf, pth)
				}
			}
			if i == 0{
				_, sent, err := sch.performPacketSendingRDDT(s, windowUpdateFrames, pth, true)
				if err != nil {
					return err
				}
				//utils.Infof("[sch]path:%v sent:%v",pth.pathID,sent)
				if sent{
					issent = true
				}
			}else{
				_, sent, err := sch.performPacketSendingRDDT(s, windowUpdateFrames, pth, false)
				//utils.Infof("[sch]path:%v sent:%v",pth.pathID,sent)
				if err != nil {
					return err
				}
				if sent{
					issent = true
				}
			}
				
			

			// And try pinging on potentially failed paths
			if fromPth != nil && fromPth.potentiallyFailed.Get() {
				err := s.sendPing(fromPth)
				if err != nil {
					return err
				}
			}
		}
		windowUpdateFrames = nil
		//utils.Infof("[ori sendpacketred]:issent?%v", issent)
		if !issent {
			// Prevent sending empty packets
			return sch.ackRemainingPaths(s, windowUpdateFrames)
		}

	}
}

func (sch *scheduler) sendPacketSTMS(s *session) error {
	var pth *path
	//utils.Infof("Here STMS \n\n")
	// Update leastUnacked value of paths
	s.pathsLock.RLock()
	for _, pthTmp := range s.paths {
		pthTmp.SetLeastUnacked(pthTmp.sentPacketHandler.GetLeastUnacked())
		
		//cx add :for zhudongdiubao
		//utils.Infof("[m]inflight: %v, room: %v",pthTmp.sentPacketHandler.GetBytesInflight(), pthTmp.sentPacketHandler.GetCWND() - pthTmp.sentPacketHandler.GetBytesInflight())
		
	}
	s.pathsLock.RUnlock()
	//sch.monitor.isAtbegining(sch, s)
	// get WindowUpdate frames
	// this call triggers the flow controller to increase the flow control windows, if necessary
	windowUpdateFrames := s.getWindowUpdateFrames(false)
	for _, wuf := range windowUpdateFrames {
		s.packer.QueueControlFrame(wuf, pth)
	}

	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	for {
		///////////////////////////////////////////
		//coderuntimestart := time.Now().UnixNano() / 1000

		sch.monitor.monitorClear()
		for pathID, pth := range s.paths {
			//utils.Infof("[sendpacketmooo]: path_id: %v", pathID)
			if !pth.SendingAllowed(sch.CWNDFlag){                                 // if path is not sendingallowed, skip this scheduling round, remember to del an item in path_order
				utils.Infof("[sc]: path %v !ALW", pathID)
				//continue
			}

			sch.monitor.monitorCurrentPathState(pth)

		}
		sch.monitor.monitorCurrentSessionState(s)
	
		numStreams := uint32(len(s.streamsMap.streams))		
		leftoverdataforwriting := 0  																 //left dataforwritingsize have not been dispatched
		dataineachstream := make(map[protocol.StreamID] int)	 //dataforwritingszie in each stream

		for j := uint32(0); j < numStreams; j++ {
			streamID := s.streamsMap.openStreams[j]
			dataineachstream[streamID] = len(s.streamsMap.streams[streamID].dataForWriting)
			leftoverdataforwriting += dataineachstream[streamID]
		}
		if(leftoverdataforwriting != 0){
			utils.Infof("[sc]Dataforwriting waitted for scheduling, size :%vB", leftoverdataforwriting)
		}
		/*order by RTT*/

		path_order, _ := sch.orderPaths(s)

		sch.monitor.isBandwidthEnough(sch, leftoverdataforwriting, s)

		///////////////////////////////////////////
		// compute gap 
		gap := make(map[uint8] int)					//gap size between paths

		//utils.Infof("[sch]------------------COMPUTE&POP--------------------")

		var i int

		for i = 0 ; ( i+1 ) < (len(path_order) - 1) ; i++ {			// -1 minus path 0 
			inx := path_order[i]
			inx1 := path_order[i+1]
			rtt0 := sch.monitor.state_owd[protocol.PathID(inx)]
			rtt1 := sch.monitor.state_owd[protocol.PathID(inx1)]
			//bw0 := sch.monitor.state_bw[protocol.PathID(inx)]
			//cw0 := sch.monitor.state_cwnd[protocol.PathID(inx)]			
			
			var computed_needed int

			if(i == 0 && rtt1 == 0 ){				// if i == 0 gap rtt1 == 0, first path need to send
				computed_needed = leftoverdataforwriting
				//utils.Infof("[sch]Path %v	gap_needed all leftoverdataforwriting, because RTT is 0", inx)
			}else{
				//n := int( rtt1 / rtt0 )
				n := int(( rtt1 - rtt0 ) / rtt0 )
				//computed_needed = int(cw0) + int(((rtt1 - rtt0).Seconds() * float64(bw0)) ) 
				for ; (leftoverdataforwriting ) -  computed_needed > 0 && n > 0 ; {
					//maxLen :=  protocol.ByteCount(cw0) + protocol.ByteCount( sch.monitor.state_inflight[protocol.PathID(inx)])
					maxLen :=  1322
					computed_needed += int(maxLen)
					n -= 1
					//utils.Infof("[sch]Path %v	computed_needed %v, n %v", inx, computed_needed, n)
				}

				if ( computed_needed >= leftoverdataforwriting ){
						computed_needed = leftoverdataforwriting
				}
				//computed_needed = 0
			}		
			//utils.Infof("[sch]Path %v	computed_needed %v, left_dataforwriting %v", inx, computed_needed, leftoverdataforwriting)
			// now change gap index, we use inx + 1 here, because previous path does not need gap 
			gap[uint8(inx1)] = int(float64(computed_needed) )
			if(gap[uint8(inx1)] < 0){
				gap[uint8(inx1)] = 0
			}
			leftoverdataforwriting -= gap[uint8(inx)]
			if(i == 0 && rtt1 == 0 ){					// if i == 0 gap rtt1 == 0, first path need to send
				break
			}
		}

		// We first check for retransmissions
		hasRetransmission, retransmitHandshakePacket, fromPth := sch.getRetransmission(s)
		// XXX There might still be some stream frames to be retransmitted
		hasStreamRetransmission := s.streamFramer.HasFramesForRetransmission()

		// Select the path here
		s.pathsLock.RLock()
		if sch.SchedulerName == "dispatch"{
			pth = sch.selectPathDispatch(s, hasRetransmission, hasStreamRetransmission, fromPth)
		}else{
			pth = sch.selectPath(s, hasRetransmission, hasStreamRetransmission, fromPth)
		}
		//utils.Infof("selected path:%v",pth.pathID)
		s.pathsLock.RUnlock()


		// XXX No more path available, should we have a new QUIC error message?
		if pth == nil {
			windowUpdateFrames := s.getWindowUpdateFrames(false)
			return sch.ackRemainingPaths(s, windowUpdateFrames)
		}

		// If we have an handshake packet retransmission, do it directly
		if hasRetransmission && retransmitHandshakePacket != nil {
			s.packer.QueueControlFrame(pth.sentPacketHandler.GetStopWaitingFrame(true), pth)
			packet, err := s.packer.PackHandshakeRetransmission(retransmitHandshakePacket, pth)
			if err != nil {
				return err
			}
			if err = s.sendPackedPacket(packet, pth, true); err != nil {
				return err
			}
			continue
		}

		// XXX Some automatic ACK generation should be done someway
		var ack *wire.AckFrame

		ack = pth.GetAckFrame()
		if ack != nil {
			s.packer.QueueControlFrame(ack, pth)
		}
		if ack != nil || hasStreamRetransmission {
			swf := pth.sentPacketHandler.GetStopWaitingFrame(hasStreamRetransmission)
			if swf != nil {
				s.packer.QueueControlFrame(swf, pth)
			}
		}

		// Also add CLOSE_PATH frames, if any
		for cpf := s.streamFramer.PopClosePathFrame(); cpf != nil; cpf = s.streamFramer.PopClosePathFrame() {
			s.packer.QueueControlFrame(cpf, pth)
		}

		// Also add ADD ADDRESS frames, if any
		for aaf := s.streamFramer.PopAddAddressFrame(); aaf != nil; aaf = s.streamFramer.PopAddAddressFrame() {
			s.packer.QueueControlFrame(aaf, pth)
		}

		// Also add PATHS frames, if any
		for pf := s.streamFramer.PopPathsFrame(); pf != nil; pf = s.streamFramer.PopPathsFrame() {
			s.packer.QueueControlFrame(pf, pth)
		}
		var err error
		var pkt *ackhandler.Packet
		var sent bool
		
		if(path_order[0] == pth.pathID && len(path_order) < 3) || sch.monitor.state_owd[pth.pathID] <= 0{
			//utils.Infof("[sch] stms -2")
			pkt, sent, err = sch.performPacketSendingSTMS(s, windowUpdateFrames, pth, -2)
		}else if(path_order[0] == pth.pathID && len(path_order) >= 3){
			//utils.Infof("[sch] stms -1")
			pkt, sent, err = sch.performPacketSendingSTMS(s, windowUpdateFrames, pth, -1)
		}else{
			utils.Infof("[sc] stms %v",gap[uint8(pth.pathID)])
			pkt, sent, err = sch.performPacketSendingSTMS(s, windowUpdateFrames, pth, int(gap[uint8(pth.pathID)]))	
		}
	
		if err != nil {
			return err
		}
		windowUpdateFrames = nil
		if !sent {
			// Prevent sending empty packets
			return sch.ackRemainingPaths(s, windowUpdateFrames)
		}
		//coderuntimeend := time.Now().UnixNano() / 1000
		//sch.totalruntime += coderuntimeend - coderuntimestart
		sch.totalpacketnum += 1
		//utils.Infof("thistime :%v totalruntime:%v, num:%v",coderuntimeend - coderuntimestart, sch.totalruntime, sch.totalpacketnum)
		
		// Duplicate traffic when it was sent on an unknown performing path
		// FIXME adapt for new paths coming during the connection
		if pth.rttStats.SmoothedRTT() == 0 {
			currentQuota := sch.quotas[pth.pathID]
			// Was the packet duplicated on all potential paths?
		duplicateLoop:
			for pathID, tmpPth := range s.paths {
				if pathID == protocol.InitialPathID || pathID == pth.pathID {
					continue
				}
				if sch.quotas[pathID] < currentQuota && tmpPth.sentPacketHandler.SendingAllowed(sch.CWNDFlag) {
					// Duplicate it
					pth.sentPacketHandler.DuplicatePacket(pkt)
					break duplicateLoop
				}
			}
		}

		// And try pinging on potentially failed paths
		if fromPth != nil && fromPth.potentiallyFailed.Get() {
			err = s.sendPing(fromPth)
			if err != nil {
				return err
			}
		}
	}
}



func (sch *scheduler) sendPacket(s *session) error {
	var pth *path
	//utils.Infof("Here rtt \n\n")
	// Update leastUnacked value of paths
	s.pathsLock.RLock()
	for _, pthTmp := range s.paths {
		pthTmp.SetLeastUnacked(pthTmp.sentPacketHandler.GetLeastUnacked())
		
		//cx add :for zhudongdiubao
		//utils.Infof("[monitor]inflight: %v, room: %v",pthTmp.sentPacketHandler.GetBytesInflight(), pthTmp.sentPacketHandler.GetCWND() - pthTmp.sentPacketHandler.GetBytesInflight())
		
	}
	s.pathsLock.RUnlock()
	sch.monitor.isAtbegining(sch, s)
	// get WindowUpdate frames
	// this call triggers the flow controller to increase the flow control windows, if necessary
	windowUpdateFrames := s.getWindowUpdateFrames(false)
	for _, wuf := range windowUpdateFrames {
		s.packer.QueueControlFrame(wuf, pth)
	}

	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	for {
		///////////////////////////////////////////
		//coderuntimestart := time.Now().UnixNano() / 1000
		sch.monitor.mutex.Lock()
		sch.monitor.monitorClear()
		for pathID, pth := range s.paths {
			//utils.Infof("[sendpacketmooo]: path_id: %v", pathID)
			if !pth.SendingAllowed(sch.CWNDFlag){                                 // if path is not sendingallowed, skip this scheduling round, remember to del an item in path_order
				utils.Infof("[sc]: path %v NOT ALLOWEND", pathID)
				//continue
			}

			sch.monitor.monitorCurrentPathState(pth)

		}
		sch.monitor.monitorCurrentSessionState(s)
		sch.monitor.mutex.Unlock()
		numStreams := uint32(len(s.streamsMap.streams))		
		leftoverdataforwriting := 0  																 //left dataforwritingsize have not been dispatched
		dataineachstream := make(map[protocol.StreamID] int)	 //dataforwritingszie in each stream

		for j := uint32(0); j < numStreams; j++ {

			streamID := s.streamsMap.openStreams[j]
			dataineachstream[streamID] = len(s.streamsMap.streams[streamID].dataForWriting)
			leftoverdataforwriting += dataineachstream[streamID]
		}
		if(leftoverdataforwriting != 0){
			
			utils.Infof("[sch]Dataforwriting waitted for scheduling, size :%vB", leftoverdataforwriting)
		}
		/*order by RTT*/

		//path_order, _ := sch.orderPaths(s)
		

		sch.monitor.isBandwidthEnough(sch, leftoverdataforwriting, s)

		///////////////////////////////////////////


		// We first check for retransmissions
		hasRetransmission, retransmitHandshakePacket, fromPth := sch.getRetransmission(s)
		// XXX There might still be some stream frames to be retransmitted
		hasStreamRetransmission := s.streamFramer.HasFramesForRetransmission()

		// Select the path here
		s.pathsLock.RLock()
		pth = sch.selectPath(s, hasRetransmission, hasStreamRetransmission, fromPth)
		s.pathsLock.RUnlock()

		// XXX No more path available, should we have a new QUIC error message?
		if pth == nil {
			windowUpdateFrames := s.getWindowUpdateFrames(false)
			// if(sch.CWNDFlag == true && sch.SchedulerName == "rtt"){
			// 	utils.Infof("change to rr")
			// 	sch.SchedulerName = "rr"
			// }
			return sch.ackRemainingPaths(s, windowUpdateFrames)
		}

		// If we have an handshake packet retransmission, do it directly
		if hasRetransmission && retransmitHandshakePacket != nil {
			s.packer.QueueControlFrame(pth.sentPacketHandler.GetStopWaitingFrame(true), pth)
			packet, err := s.packer.PackHandshakeRetransmission(retransmitHandshakePacket, pth)
			if err != nil {
				return err
			}
			if err = s.sendPackedPacket(packet, pth, true); err != nil {
				return err
			}
			continue
		}

		// XXX Some automatic ACK generation should be done someway
		var ack *wire.AckFrame

		ack = pth.GetAckFrame()
		if ack != nil {
			s.packer.QueueControlFrame(ack, pth)
		}
		if ack != nil || hasStreamRetransmission {
			swf := pth.sentPacketHandler.GetStopWaitingFrame(hasStreamRetransmission)
			if swf != nil {
				s.packer.QueueControlFrame(swf, pth)
			}
		}

		// Also add CLOSE_PATH frames, if any
		for cpf := s.streamFramer.PopClosePathFrame(); cpf != nil; cpf = s.streamFramer.PopClosePathFrame() {
			s.packer.QueueControlFrame(cpf, pth)
		}

		// Also add ADD ADDRESS frames, if any
		for aaf := s.streamFramer.PopAddAddressFrame(); aaf != nil; aaf = s.streamFramer.PopAddAddressFrame() {
			s.packer.QueueControlFrame(aaf, pth)
		}

		// Also add PATHS frames, if any
		for pf := s.streamFramer.PopPathsFrame(); pf != nil; pf = s.streamFramer.PopPathsFrame() {
			s.packer.QueueControlFrame(pf, pth)
		}

		pkt, sent, err := sch.performPacketSending(s, windowUpdateFrames, pth)
		if err != nil {
			return err
		}
		windowUpdateFrames = nil
		if !sent {
			// Prevent sending empty packets
			return sch.ackRemainingPaths(s, windowUpdateFrames)
		}
		//coderuntimeend := time.Now().UnixNano() / 1000
		//sch.totalruntime += coderuntimeend - coderuntimestart
		sch.totalpacketnum += 1
		//utils.Infof("thistime :%v,totalruntime:%v, num:%v",coderuntimeend - coderuntimestart,sch.totalruntime, sch.totalpacketnum)
		
		// Duplicate traffic when it was sent on an unknown performing path
		// FIXME adapt for new paths coming during the connection
		if pth.rttStats.SmoothedRTT() == 0 {
			currentQuota := sch.quotas[pth.pathID]
			// Was the packet duplicated on all potential paths?
		duplicateLoop:
			for pathID, tmpPth := range s.paths {
				if pathID == protocol.InitialPathID || pathID == pth.pathID {
					continue
				}
				if sch.quotas[pathID] < currentQuota && tmpPth.sentPacketHandler.SendingAllowed(sch.CWNDFlag) {
					// Duplicate it
					pth.sentPacketHandler.DuplicatePacket(pkt)
					break duplicateLoop
				}
			}
		}

		// And try pinging on potentially failed paths
		if fromPth != nil && fromPth.potentiallyFailed.Get() {
			err = s.sendPing(fromPth)
			if err != nil {
				return err
			}
		}
	}
}

func (sch *scheduler) orderPaths(s *session)([]protocol.PathID, int){
	var path_order []protocol.PathID
	for i,_ := range s.paths{
		if(i!=protocol.InitialPathID){
			path_order = append(path_order, i)
		}
	}

	var min int 
	var inx int
	for i, ori := range path_order {                      //sort based on rtt of each path
		//pthi := s.paths[ori]
		//min = int(pthi.rttStats.SmoothedRTT())
		min = int(sch.monitor.state_owd[ori])
		inx = i
		var tmp protocol.PathID
		//pthi := s.paths[ori]
		//utils.Infof("[sendpacketmooo]: min:%v path_id_inx:%v",min,inx)
		for j, orj := range path_order {
			if j < i {						//sort 
				continue
			}
			//pthj := s.paths[orj]
			now := int(sch.monitor.state_owd[orj])
			//if(j == protocol.InitialPathID || !pthj.SendingAllowed()){                         //when mp, skip initialpathid and Sengding not allowed paths.
			if(j == protocol.InitialPathID){
				continue
			}
			//if (now < min && now != 0) || (now > min && min == 0) || (!pthi.SendingAllowed() && pthj.SendingAllowed()){		//e.g. p1 = 0 && p3 = 10, thus exchange p1 and p3
			if (now < min && now != 0) || (now > min && min == 0) {
				min = now
				inx = j
			}
		}
		tmp = path_order[inx]
		path_order[inx] = path_order[i]
		path_order[i] = tmp
	}
	path_order = append(path_order, protocol.PathID(0))
	utils.Infof("[sc]Path_order: %v", path_order)
	return path_order,min
}


func (m *monitor) monitorClear(){
	m.totalbw = 0
	m.totalcwnd = 0
	m.retransBytes = 0
}

func (m *monitor) monitorCurrentPathState(pth *path) {
	nowRTT := pth.rttStats.SmoothedRTT()
	/*monitor info*/
	m.state_owd[pth.pathID] = nowRTT  / 2           // owd
	m.state_bw[pth.pathID] = int64(pth.sentPacketHandler.GetBandwidthEstimate())   //bw
	m.state_loss[pth.pathID] = float64(pth.sentPacketHandler.GetLossRate())
	m.state_cwnd[pth.pathID] = int64(pth.sentPacketHandler.GetCWND() - pth.sentPacketHandler.GetBytesInflight()) //cwnd
	m.state_inflight[pth.pathID] = int64(pth.sentPacketHandler.GetBytesInflight())
	
	if(pth.pathID != protocol.PathID(0) &&  int64(m.state_owd[pth.pathID]) > 0 ) {
		
		m.totalbw += ( float64(m.state_cwnd[pth.pathID]) / (float64(m.state_owd[pth.pathID]) / 1000000000.0))
		m.totalcwnd += m.state_cwnd[pth.pathID]
		m.retransBytes += pth.sentPacketHandler.GetLostByte()
	}
	//utils.Infof("[m]Path %v	rtt: %v, bw: %v, cwnd: %v, loss_rate: %v",pth.pathID, nowRTT, m.state_bw[pth.pathID], m.state_cwnd[pth.pathID], m.state_loss[pth.pathID])
	utils.Infof("[m]Path %v	rtt: %v,  cwnd: %v, loss: %v",pth.pathID, nowRTT, m.state_cwnd[pth.pathID], m.state_loss[pth.pathID])
	utils.Infof("[m]retransBytes:%vB", m.retransBytes)
	//utils.Infof("[monitor]path %v, inflight %v, serverinx %v,", pth.pathID,  m.state_inflight[pth.pathID], m.state_serverinx[pth.pathID])
	
}

func (m *monitor) monitorCurrentSessionState(s *session){

	
	numStreams := uint32(len(s.streamsMap.streams))					
	for j := uint32(0); j < numStreams; j++ {
		streamID := s.streamsMap.openStreams[j]
		if(streamID == protocol.StreamID(3)){
			//utils.Infof("[m]rcvbuf: %v", len(s.streamsMap.streams[streamID].frameQueue.queuedFrames))
			utils.Infof("[m]dupsize: %vB", s.streamsMap.streams[streamID].frameQueue.dupframesize)
		}

	}
	//utils.Infof("[m]retransBytes: %vB", m.retransBytes)
}

func (m *monitor) isHighlossrate(sch *scheduler, s *session){
	var highloss_flag	bool
	highloss_flag = false
	for _, path := range s.paths{
		pid := path.pathID
		if(pid != protocol.InitialPathID){
			if(sch.monitor.state_loss[pid] > 0.02){
				sch.Flag_high_lossrate = true
				highloss_flag = true
				if(sch.SchedulerName == "moooko"){
					sch.SchedulerName = "redundancy"
				}
				utils.Infof("high loss rate %v now change to red", sch.monitor.state_loss[pid] )
			}

		}
	}
	if( highloss_flag == false && sch.Flag_high_lossrate == true && sch.SchedulerName == "redundancy" ){
		sch.Flag_high_lossrate = false
		sch.SchedulerName = "moooko"
		utils.Infof("low loss rate now change back to moooko" )
	}
}
func (m *monitor) isBandwidthEnough(sch *scheduler, leftoverdataforwriting int, s *session){
	// // solution 1.
	// T_video := time.Duration( float64( 1 / m.fps) * 1000 ) * time.Millisecond
	// rtt_min := ( time.Duration( min ) / 1000000 ) * time.Millisecond

	//d := int64(leftoverdataforwriting) - sch.monitor.totalbw // data can't be sent in this iteration, no space
	// utils.Infof("[sch]d: %v, T_video:%v, min:%v",d,T_video,rtt_min)
	// //if sch.Flag_bw_unenough == false && len(path_order) >= 2 && ((T_video < time.Duration(min) && d > 0) || (T_video >=  time.Duration(min) && T_video < sch.monitor.state_owd[path_order[1]] * 2 && d > sch.monitor.state_cwnd[path_order[1]])){
	// if sch.Flag_bw_unenough == false && len(path_order) >= 2 && (T_video < time.Duration(rtt_min) && d > 0){
	// 	sch.Flag_bw_unenough = true
	// 	sch.Limit = 100000
	// 	utils.Infof("[monitor]Network state change into \033[44;37;5m Bandwidth unenough \033[0m")
	// }
	// //if  sch.Flag_bw_unenough == true && len(path_order) >= 2 && ( d <= 0 || (d <= sch.monitor.state_cwnd[path_order[1]] && T_video >= sch.monitor.state_owd[path_order[1]] * 2  )){
	// if  sch.Flag_bw_unenough == true && len(path_order) >= 2 && ( d <= 0 || (d <= sch.monitor.state_cwnd[path_order[1]] && T_video >= sch.monitor.state_owd[path_order[1]] * 2  )){
	// 		sch.Limit = 100000
	// 		utils.Infof("[monitor]Network state change into \033[44;37;5m Bandwidth enough \033[0m")
	// 		sch.Flag_bw_unenough = false
	// }

	// solution 2.
	//utils.Infof("[m]totalbw:%v, totalcwnd:%v bitrate:%v", m.totalbw, int(m.totalcwnd), m.bitrate)
	// if(m.totalbw == 0){
	// 	return
	// }

	// To fix : AI interface !!!!!!!!!!!!!!!!!!
	if( m.totalbw + 2700000 < m.bitrate  && len(s.paths) >= 3 && sch.totalpacketnum > 30000){
	//if( m.totalbw   < 0 && leftoverdataforwriting > 0){
		//sch.Flag_bw_unenough = true
		m.lackbw = true
		utils.Infof("[m] lackbw :%v, totalbw :%v",m.lackbw, m.totalbw)
	}else{
		m.lackbw = false
		//sch.Flag_bw_unenough = false
		//utils.Infof("[monitor] Bandwidth enough")
	}
}

func (m *monitor) isAtbegining(sch *scheduler, s *session){
	var RTT0_flag	bool
	RTT0_flag = false
	for _, path := range s.paths{
		pid := path.pathID
		if( len(s.paths) < 3){
			RTT0_flag = true
			sch.Flag_beginining = true
			if(sch.SchedulerName == "moooko" ){
				sch.SchedulerName = "rtt"
				utils.Infof("WARMUP! Begining from rtt" )
			}
		}
		if(pid != protocol.InitialPathID){
			if(path.rttStats.SmoothedRTT() == 0){
				RTT0_flag = true
				sch.Flag_beginining = true
				if(sch.SchedulerName == "moooko" ){
					sch.SchedulerName = "rtt"
					utils.Infof("WARMUP! Begining from rtt" )
				}
				
			}

		}
	}

	if( RTT0_flag  == false && sch.Flag_beginining == true && sch.SchedulerName == "rtt" && sch.OriginScheduler == "moooko"){
		sch.Flag_beginining  = false
		sch.SchedulerName = "moooko"
		utils.Infof("WARMUP END! Back to moooko" )
	}
}


