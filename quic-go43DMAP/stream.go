package quic

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"errors"
	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// A Stream assembles the data from StreamFrames and provides a super-convenient Read-Interface
//
// Read() and Write() may be called concurrently, but multiple calls to Read() or Write() individually must be synchronized manually.
type stream struct {
	mutex sync.Mutex

	ctx       context.Context
	ctxCancel context.CancelFunc

	streamID protocol.StreamID
	onData   func()
	// onReset is a callback that should send a RST_STREAM
	onReset func(protocol.StreamID, protocol.ByteCount)

	readPosInFrame int
	writeOffset    protocol.ByteCount
	readOffset     protocol.ByteCount

	// Once set, the errors must not be changed!
	err error

	// cancelled is set when Cancel() is called
	cancelled utils.AtomicBool
	// finishedReading is set once we read a frame with a FinBit
	finishedReading utils.AtomicBool
	// finisedWriting is set once Close() is called
	finishedWriting utils.AtomicBool
	// resetLocally is set if Reset() is called
	resetLocally utils.AtomicBool
	// resetRemotely is set if RegisterRemoteError() is called
	resetRemotely utils.AtomicBool

	frameQueue   *streamFrameSorter
	readChan     chan struct{}
	readDeadline time.Time

	dataForWriting []byte
	finSent        utils.AtomicBool
	rstSent        utils.AtomicBool
	writeChan      chan struct{}
	writeDeadline  time.Time

	flowControlManager flowcontrol.FlowControlManager

	localaddr string
	remoteaddr string

	I_startinx int // cx add
	I_endinx int // cx add
	

	Iframecount int // cx add for test
	hasI	bool //cx add

	NextHeaderOff []int // mark header 
	
	sess *session

	writeOffsetF	protocol.ByteCount
	writeOffsetSN 	protocol.ByteCount
	writeOffsetSS 	protocol.ByteCount

	gap protocol.ByteCount

	cansendpattern bool
}

var _ Stream = &stream{}

type deadlineError struct{}

func (deadlineError) Error() string   { return "deadline exceeded" }
func (deadlineError) Temporary() bool { return true }
func (deadlineError) Timeout() bool   { return true }

var errDeadline net.Error = &deadlineError{}

// newStream creates a new Stream
func newStream(sess *session, StreamID protocol.StreamID,
	onData func(),
	onReset func(protocol.StreamID, protocol.ByteCount),
	flowControlManager flowcontrol.FlowControlManager) *stream {
	s := &stream{
		sess:	sess,
		onData:             onData,
		onReset:            onReset,
		streamID:           StreamID,
		flowControlManager: flowControlManager,
		frameQueue:         newStreamFrameSorter(),
		readChan:           make(chan struct{}, 1),
		writeChan:          make(chan struct{}, 1),
	}
	s.ctx, s.ctxCancel = context.WithCancel(context.Background())
	s.I_startinx = -1		//cx add
	s.I_endinx = -1
	s.hasI = false
	s.NextHeaderOff = make([]int, 1)
	s.NextHeaderOff[0] = -3
	s.cansendpattern = true
	return s
}


//cx add :find I frame
func(s *stream)FindIframe(){
	//utils.Infof("[str]dataforwriting:%v",s.dataForWriting)
	tmp := make([]int, 30)
	countheader := 0
	for i:=0; i< len(s.dataForWriting) - 12 ; i++ {
		p := s.dataForWriting[i]
		p1 := s.dataForWriting[i+1]
		p7 := s.dataForWriting[i+7]
		p8 := s.dataForWriting[i+8]
		p12 := s.dataForWriting[i + 12]
		if(p == 6 && p1 == 0 && p7 == 8 && p8 == 1) || (p == 7 && p1 == 0 && p7 == 9 && p8 == 1 && (p12 == 23 || p12 == 39)){
			//utils.Infof("[str]%v",p12)
			//s.NextHeaderOff = i 
			tmp[countheader] = i
			countheader += 1
			utils.Infof("[str]find key %v i_start: %v, nextheaderoff:%v ,cnt:%v",s.dataForWriting[i:i+13], s.I_startinx, i, countheader)
			// handle I-frame header
			if(s.I_startinx != -1){
				if(i != 0){
					s.I_endinx = i - 1 
				}else{
					s.I_endinx = -2
				}
				//utils.Infof("[str]find I frame: start from :%v  end to :%v",s.I_startinx, s.I_endinx)
				
				// s.I_startinx = -1
				// s.I_endinx = -1
				break
			}
			if(s.I_startinx == -1 && p ==7 && p12 == 23){
				s.I_startinx = i
				s.hasI = true
				s.Iframecount += 1 
				utils.Infof("[str]find I frame: start %v %v ",s.dataForWriting[i:i+13], i)
			}
			
		}
	}
	if(countheader == 0){
		s.NextHeaderOff = make([]int, 1)
		s.NextHeaderOff[0] = -1
	}else{
		s.NextHeaderOff = make([]int, countheader)
		copy(s.NextHeaderOff, tmp[:countheader])
	}
}

// Read implements io.Reader. It is not thread safe!
func (s *stream) Read(p []byte) (int, error) {
	s.mutex.Lock()
	err := s.err
	s.mutex.Unlock()
	if s.cancelled.Get() || s.resetLocally.Get() {
		return 0, err
	}
	if s.finishedReading.Get() {
		return 0, io.EOF
	}

	bytesRead := 0
	for bytesRead < len(p) {
		s.mutex.Lock()
		frame := s.frameQueue.Head()
		if frame == nil && bytesRead > 0 {
			//utils.Infof("noread %v, pos:%v, gaps:%v",s.frameQueue.queuedFrames, s.frameQueue.readPosition, s.frameQueue.gaps.Front())
			err = s.err
			s.mutex.Unlock()
			//utils.Infof("frame nil so return, bytes:%v",bytesRead)
			return bytesRead, err
			//continue //cx add!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!origin is return bytesRead,rr
		}

		var err error



		for {
			// Stop waiting on errors
			if s.resetLocally.Get() || s.cancelled.Get() {
				err = s.err
				break
			}

			deadline := s.readDeadline
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				err = errDeadline
				break
			}

			if frame != nil {
				s.readPosInFrame = int(s.readOffset - frame.Offset)
				//utils.Infof("frameread:%v,DATALEN:%v",frame,frame.DataLen())
				if( frame.DataLen() >= 4 && frame.Data[0] == byte(97) && frame.Data[1] == byte(98) && frame.Data[2] == byte(99) && frame.Data[3] == byte(100)){
					
					if(frame.DataLen() == 4){
						
						s.mutex.Unlock()
						m := utils.Min(len(p)-bytesRead, int(frame.DataLen())-s.readPosInFrame)
						copy(p[bytesRead:], frame.Data[s.readPosInFrame:])
						s.readPosInFrame += m
						bytesRead += m
						s.readOffset += protocol.ByteCount(m)
						if !s.resetRemotely.Get() {
							s.flowControlManager.AddBytesRead(s.streamID, protocol.ByteCount(m))
						}
						s.onData() // so that a possible WINDOW_UPDATE is sent
						if s.readPosInFrame >= int(frame.DataLen()) {
							s.mutex.Lock()
							s.frameQueue.Pop()
							s.mutex.Unlock()
						}
						utils.Infof("find discard pattern!!!!%vret :%v",frame,bytesRead)
						return bytesRead, errors.New("find discard err")
					}
					
				}
				break
			}

			s.mutex.Unlock()
			if deadline.IsZero() {
				<-s.readChan
			} else {
				select {
				case <-s.readChan:
				case <-time.After(deadline.Sub(time.Now())):
				}
			}
			s.mutex.Lock()
			frame = s.frameQueue.Head()
		}
		s.mutex.Unlock()

		if err != nil {
			return bytesRead, err
		}

		m := utils.Min(len(p)-bytesRead, int(frame.DataLen())-s.readPosInFrame)

		if bytesRead > len(p) {
			return bytesRead, fmt.Errorf("BUG: bytesRead (%d) > len(p) (%d) in stream.Read", bytesRead, len(p))
		}
		if s.readPosInFrame > int(frame.DataLen()) {
			return bytesRead, fmt.Errorf("BUG: readPosInFrame (%d) > frame.DataLen (%d) in stream.Read", s.readPosInFrame, frame.DataLen())
		}
		copy(p[bytesRead:], frame.Data[s.readPosInFrame:])
		//utils.Infof("copy frame data :%v",frame.Data[s.readPosInFrame:])

		s.readPosInFrame += m
		bytesRead += m
		s.readOffset += protocol.ByteCount(m)

		// when a RST_STREAM was received, the was already informed about the final byteOffset for this stream
		if !s.resetRemotely.Get() {
			s.flowControlManager.AddBytesRead(s.streamID, protocol.ByteCount(m))
		}
		s.onData() // so that a possible WINDOW_UPDATE is sent

		if s.readPosInFrame >= int(frame.DataLen()) {
			fin := frame.FinBit
			s.mutex.Lock()
			s.frameQueue.Pop()
			s.mutex.Unlock()
			if fin {
				s.finishedReading.Set(true)
				return bytesRead, io.EOF
			}
		}
	}
	//utils.Infof("[str]have read:%v bytes, now offset:%v", bytesRead, s.frameQueue.readPosition)
	return bytesRead, nil
}


func (s *stream)GetSession()(*session){
	return s.sess
}

func (s *stream) Write(p []byte) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resetLocally.Get() || s.err != nil {
		return 0, s.err
	}
	if s.finishedWriting.Get() {
		return 0, fmt.Errorf("write on closed stream %d", s.streamID)
	}
	if len(p) == 0 {
		return 0, nil
	}
	//utils.Infof("[str]		new data:%v \n",p)
	s.dataForWriting = make([]byte, len(p))
	copy(s.dataForWriting, p)
	//utils.Infof("[str]		streamID :%v, NEW WRITE dataforwriting len:%v",s.streamID, len(p))
	////////////////  cx add priority I frames
	if(s.sess.config.IPriority ){
		s.FindIframe()
	}
	///////////////////////////////////
	
	s.onData()

	var err error
	for {
		deadline := s.writeDeadline
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			
			err = errDeadline
			break
		}
		if s.dataForWriting == nil || s.err != nil {
			//s.duration_writing = 0 
			break
		}

		s.mutex.Unlock()
		if deadline.IsZero() {

			// s.duration_writing +=1 
			<-s.writeChan
		} else {
			select {
			case <-s.writeChan:
			case <-time.After(deadline.Sub(time.Now())):
			}
		}
		s.mutex.Lock()
	}

	if err != nil {
		return 0, err
	}
	if s.err != nil {
		return len(p) - len(s.dataForWriting), s.err
	}
	
	return len(p), nil
}

func (s *stream) lenOfDataForWriting() protocol.ByteCount {
	s.mutex.Lock()
	var l protocol.ByteCount
	if s.err == nil {
		l = protocol.ByteCount(len(s.dataForWriting))
	}
	s.mutex.Unlock()
	return l
}


func (s *stream) getDataForWriting(maxBytes protocol.ByteCount) []byte {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.err != nil || s.dataForWriting == nil {
		return nil
	}

	var ret []byte
	//utils.Infof("[str]dataoff:%v",s.writeOffset)
	if protocol.ByteCount(len(s.dataForWriting)) > maxBytes {
		ret = s.dataForWriting[:maxBytes]
		s.dataForWriting = s.dataForWriting[maxBytes:]
	} else {
		ret = s.dataForWriting
		s.dataForWriting = nil
		s.signalWrite()
	}

	s.writeOffset += protocol.ByteCount(len(ret))
	//utils.Infof("[str]		writeoffset: 0x%x",s.writeOffset)
	return ret
}

func (s *stream) getDataForWritingSTMS(maxBytes protocol.ByteCount, gap  int, path_id protocol.PathID) []byte {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.err != nil || s.dataForWriting == nil {
		return nil
	}
	var ret []byte
	//utils.Infof("dataforwriting:%v", s.dataForWriting)
	if(gap < 0){
		utils.Infof("[str]	in fast path")
		if(gap == -1){
			//fastest path and three paths
			if protocol.ByteCount(len(s.dataForWriting)) > maxBytes {
				ret = s.dataForWriting[:maxBytes]
				if((s.writeOffsetF + protocol.ByteCount(len(ret)) > s.writeOffsetSS) && (s.writeOffsetF < s.writeOffsetSS)){
					// 快路比慢路起点低，且快路此次会超过慢路起点。所以只能传到慢路起点前的部分
					utils.Infof("[str]	1")
					utils.Infof("this now :%v len ret:%v > other start:%v", s.writeOffsetF, len(ret), s.writeOffsetSS)
					//ret = make([]byte, len(s.dataForWriting[:s.writeOffsetSS - s.writeOffsetF]))
					//copy(ret, s.dataForWriting[:s.writeOffsetSS - s.writeOffsetF])
					ret =  s.dataForWriting[:s.writeOffsetSS - s.writeOffsetF]
					utils.Infof("fast path %v, before split by gap :%v, ret len:%v",path_id, len(s.dataForWriting), len(ret))
					s.dataForWriting = s.dataForWriting[ (s.writeOffsetSS - s.writeOffsetF):]
					s.writeOffsetF = s.writeOffsetSN
					s.writeOffsetSS = s.writeOffsetSN
					utils.Infof("after split by gap :%v,  writeoffnow:%v",len(s.dataForWriting), s.writeOffsetF)
					s.gap = 0			//gap have been filled
				}else if ((s.writeOffsetF + protocol.ByteCount(len(ret)) <= s.writeOffsetSS) && (s.writeOffsetF < s.writeOffsetSS)){
					// 快路比慢路起点低，且快路不会超过慢路起点。慢路继续按照原offset传输，但s.gap减小
					utils.Infof("this now :%v len ret:%v <= other start:%v", s.writeOffsetF, len(ret), s.writeOffsetSS)
					ret = s.dataForWriting[:maxBytes]
					//ret = make([]byte, len(s.dataForWriting[:maxBytes]))
					//copy(ret, s.dataForWriting[:maxBytes])
					s.dataForWriting = s.dataForWriting[maxBytes:]
					s.writeOffsetF += protocol.ByteCount(len(ret))
					s.gap -= protocol.ByteCount(len(ret))
					utils.Infof("[str]	2")
					
				}else if(s.writeOffsetF == s.writeOffsetSS){
					// 
					utils.Infof("[str]	3")
					s.writeOffsetF = s.writeOffsetSN
					s.writeOffsetSS = s.writeOffsetSN
					s.dataForWriting = s.dataForWriting[maxBytes:]
					s.writeOffsetF += protocol.ByteCount(len(ret))
					s.writeOffsetSS += protocol.ByteCount(len(ret))
					s.writeOffsetSN += protocol.ByteCount(len(ret))
					s.gap = 0
					
				}else{
					// 快路比慢路起点高
					//utils.Infof("[str]	4")
					utils.Infof("ERROR CASE")
				}
				
			}else{
				ret = s.dataForWriting
				if((s.writeOffsetF + protocol.ByteCount(len(ret)) >= s.writeOffsetSS) && (s.writeOffsetF < s.writeOffsetSS)){
					//utils.Infof("[str]	4")
					//utils.Infof("this now :%v + len ret:%v > other start:%v", s.writeOffsetF, len(ret), s.writeOffsetSS)
					//ret = make([]byte, len(s.dataForWriting[:s.writeOffsetSS - s.writeOffsetF]))
					//copy(ret, s.dataForWriting[:s.writeOffsetSS - s.writeOffsetF])
					ret =  s.dataForWriting[:s.writeOffsetSS - s.writeOffsetF]
					//utils.Infof("fast path %v, before split by gap :%v, ret len:%v",path_id, len(s.dataForWriting), len(ret))
					s.dataForWriting = s.dataForWriting[s.writeOffsetSS - s.writeOffsetF:]
					s.writeOffsetF = s.writeOffsetSN
					s.writeOffsetSS = s.writeOffsetSN
					s.gap = 0
					utils.Infof("after split by gap :%v,  writeoffnow:%v",len(s.dataForWriting), s.writeOffsetF)
				}else if ((s.writeOffsetF + protocol.ByteCount(len(ret)) < s.writeOffsetSS) && (s.writeOffsetF < s.writeOffsetSS)){
					//utils.Infof("[str]	5")
					utils.Infof("ERROR CASE")  // ONCE MAXBYTES > DATAFORWRITING, S.WRITEOFFSETF+MAYBYTES WILL OVER WRITEOFFSETSS

				}else if(s.writeOffsetF == s.writeOffsetSS){
					//utils.Infof("[str]	6")
					s.writeOffsetF = s.writeOffsetSN
					s.writeOffsetSS = s.writeOffsetSN
					s.dataForWriting = nil
					s.signalWrite()
					s.writeOffsetF += protocol.ByteCount(len(ret))
					s.writeOffsetSS += protocol.ByteCount(len(ret))
					s.writeOffsetSN += protocol.ByteCount(len(ret))
					s.gap = 0
					//utils.Infof("[str]	stms writeoffsetnow change:%v, lenret:%v", s.writeOffsetF, len(ret))
				}else{
					//utils.Infof("[str]	7")
					utils.Infof("ERROR CASE")

				}
				
			}
			if(len(s.dataForWriting) == 0){
				s.dataForWriting = nil
				s.signalWrite()
			}
			utils.Infof("[str]	stms writeoffsetnow change:%v, lenret:%v", s.writeOffsetF, len(ret))
		}else if(gap == -2){
			// fastest path and no enough paths
			if protocol.ByteCount(len(s.dataForWriting)) > maxBytes {
				ret = s.dataForWriting[:maxBytes]
				s.dataForWriting = s.dataForWriting[maxBytes:]
			}else{
				ret = s.dataForWriting
				s.dataForWriting = nil
				s.signalWrite()
			}
			s.writeOffsetF += protocol.ByteCount(len(ret))
			s.writeOffsetSS += protocol.ByteCount(len(ret))
			s.writeOffsetSN += protocol.ByteCount(len(ret))
			//utils.Infof("[str]	stms writeoffsetnow change:%v, lenret:%v", s.writeOffsetF, len(ret))
		}
		//utils.Infof("[str]		writeoffset: 0x%x",s.writeOffset)
		
	}else{
		// slower path, gap it
		//utils.Infof("[str]	in slower path")
		if( protocol.ByteCount(gap) >= protocol.ByteCount(len(s.dataForWriting)) ){
			// gap大于数据长度，且起点和现在位置相同
			//utils.Infof("[str]	1")
			return nil
		}else if (protocol.ByteCount(gap) < protocol.ByteCount(len(s.dataForWriting)) && s.writeOffsetSN > s.writeOffsetSS ){
			// 起点和现在位置不同
			if protocol.ByteCount(len(s.dataForWriting[s.gap :])) > maxBytes {
				//utils.Infof("[str]	2")
				//ret = s.dataForWriting[s.gap :s.gap+maxBytes]
				ret = make([]byte, len(s.dataForWriting[s.gap :s.gap+maxBytes]))
				copy(ret, s.dataForWriting[s.gap :s.gap+maxBytes])
				//s.dataForWriting = s.dataForWriting[maxBytes:]
				//utils.Infof("slower path %v, before split by gap :%v, ret len:%v",path_id, len(s.dataForWriting), len(ret))
				//utils.Infof("s.dataForWriting[:s.gap]:%v, s.dataForWriting[s.gap+maxBytes:]:%v,maxbytes:%v",len(s.dataForWriting[:s.gap]),len(s.dataForWriting[s.gap+maxBytes:]), maxBytes)
				s.dataForWriting = append(s.dataForWriting[:s.gap], s.dataForWriting[s.gap+maxBytes:]...)
				
			}else{
				
				//utils.Infof("[str]	3")
				ret = make([]byte, len(s.dataForWriting[s.gap:]))
				//copy(ret, s.dataForWriting[s.gap:])
				ret = s.dataForWriting[s.gap:]
				//utils.Infof("s.dataForWriting[:s.gap]:%v, s.dataForWriting[s.gap:]:%v",len(s.dataForWriting[:s.gap]),len(s.dataForWriting[s.gap:]))
				s.dataForWriting = s.dataForWriting[:s.gap]
				if(len(ret) == 0){
					//utils.Infof("[str]	3nil")
					ret = nil
				}
				//s.signalWrite()
			}
			s.writeOffsetSN += protocol.ByteCount(len(ret))
			//utils.Infof("[str]	stms writeoffsetSN change:%v, lenret:%v", s.writeOffsetSN, len(ret))
		}else{
			// gap<数据长度, 且start == now，开始一段新的s.gap计算。注意：如果其他路发送了，那s.gap就需要重新计算了
			//utils.Infof("[str]	4")
			//utils.Infof("gap %v < dataforrwriting :%v start %v == now %v", gap, protocol.ByteCount(len(s.dataForWriting)), s.writeOffsetSS,s.writeOffsetSN)
			s.gap = protocol.ByteCount(gap)
			if protocol.ByteCount(len(s.dataForWriting[gap:])) > maxBytes {
				//utils.Infof("[str]	5")
				ret = make([]byte, len(s.dataForWriting[gap:gap+int(maxBytes)]))
				copy(ret,s.dataForWriting[gap:gap+int(maxBytes)])
				//ret = s.dataForWriting[gap:gap+int(maxBytes)]
				//utils.Infof("s.dataForWriting[:gap]:%v,lenret:%v, s.dataForWriting[gap+int(maxBytes):]:%v",len(s.dataForWriting[:gap]),len(ret), len(s.dataForWriting[gap+int(maxBytes):]))
				//s.dataForWriting = s.dataForWriting[maxBytes:]
				//utils.Infof("slower path %v, before split by gap :%v, ret len:%v",path_id, len(s.dataForWriting), len(ret))
				s.dataForWriting = append(s.dataForWriting[:gap], s.dataForWriting[gap+int(maxBytes):]...)
			}else{
				//utils.Infof("[str]	6")
				ret = make([]byte, len(s.dataForWriting[gap :]))
				copy(ret,s.dataForWriting[gap :])
				//ret = s.dataForWriting[gap :]
				//utils.Infof("s.dataForWriting[:gap]:%v, s.dataForWriting[gap:]:%v",len(s.dataForWriting[:gap]),len(s.dataForWriting[gap:]))
		
				s.dataForWriting = s.dataForWriting[:gap]
				s.gap = protocol.ByteCount(gap)
				//s.signalWrite()
			}
			s.writeOffsetSS += protocol.ByteCount(gap)
			s.writeOffsetSN = s.writeOffsetSS + protocol.ByteCount(len(ret) )
			//utils.Infof("after split by gap :%v, writeoffstart:%v, writeoffnow:%v",len(s.dataForWriting), s.writeOffsetSS, s.writeOffsetSN)
		}
		if(len(s.dataForWriting) == 0){
			s.dataForWriting = nil
			s.signalWrite()
		}
	}

	return ret
}

// Close implements io.Closer
func (s *stream) Close() error {
	s.finishedWriting.Set(true)
	s.ctxCancel()
	s.onData()
	return nil
}

func (s *stream) shouldSendReset() bool {
	if s.rstSent.Get() {
		return false
	}
	return (s.resetLocally.Get() || s.resetRemotely.Get()) && !s.finishedWriteAndSentFin()
}

func (s *stream) shouldSendFin() bool {
	s.mutex.Lock()
	res := s.finishedWriting.Get() && !s.finSent.Get() && s.err == nil && s.dataForWriting == nil
	s.mutex.Unlock()
	return res
}

func (s *stream) sentFin() {
	s.finSent.Set(true)
}

// AddStreamFrame adds a new stream frame
func (s *stream) AddStreamFrame(frame *wire.StreamFrame) error {
	//utils.Infof("[str]gaps content:%v",s.frameQueue.gaps)
	maxOffset := frame.Offset + frame.DataLen()
	// /utils.Infof("[str]add streamframe :%v,off:%v,datalen:%v", frame,frame.Offset,frame.DataLen())
	err := s.flowControlManager.UpdateHighestReceived(s.streamID, maxOffset)
	if err != nil {
		return err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	err = s.frameQueue.Push(frame)
	//gap := s.frameQueue.gaps.Len()
	//utils.Debugf("streamgap:%de",gap)
	
	if err != nil && err != errDuplicateStreamData {
		return err
	}
	s.signalRead()
	return nil
}

// signalRead performs a non-blocking send on the readChan
func (s *stream) signalRead() {
	select {
	case s.readChan <- struct{}{}:
	default:
	}
}

// signalRead performs a non-blocking send on the writeChan
func (s *stream) signalWrite() {
	select {
	case s.writeChan <- struct{}{}:
	default:
	}
}

func (s *stream) SetReadDeadline(t time.Time) error {
	s.mutex.Lock()
	oldDeadline := s.readDeadline
	s.readDeadline = t
	s.mutex.Unlock()
	// if the new deadline is before the currently set deadline, wake up Read()
	if t.Before(oldDeadline) {
		s.signalRead()
	}
	return nil
}

func (s *stream) SetWriteDeadline(t time.Time) error {
	s.mutex.Lock()
	oldDeadline := s.writeDeadline
	s.writeDeadline = t
	s.mutex.Unlock()
	if t.Before(oldDeadline) {
		s.signalWrite()
	}
	return nil
}

func (s *stream) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)  // SetReadDeadline never errors
	_ = s.SetWriteDeadline(t) // SetWriteDeadline never errors
	return nil
}

// CloseRemote makes the stream receive a "virtual" FIN stream frame at a given offset
func (s *stream) CloseRemote(offset protocol.ByteCount) {
	s.AddStreamFrame(&wire.StreamFrame{FinBit: true, Offset: offset})
}

// Cancel is called by session to indicate that an error occurred
// The stream should will be closed immediately
func (s *stream) Cancel(err error) {
	s.mutex.Lock()
	s.cancelled.Set(true)
	s.ctxCancel()
	// errors must not be changed!
	if s.err == nil {
		s.err = err
		s.signalRead()
		s.signalWrite()
	}
	s.mutex.Unlock()
}
// LocalAddr returns the local address.
func (s *stream) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr returns the address of the peer.
func (s *stream) RemoteAddr() net.Addr {
	return nil
}
func (s *stream) SetLocalAddr(addr string)  {
	s.localaddr = addr 
}

// RemoteAddr returns the address of the peer.
func (s *stream) SetRemoteAddr(addr string)  {
	s.remoteaddr=addr
}
// resets the stream locally
func (s *stream) Reset(err error) {
	if s.resetLocally.Get() {
		return
	}
	s.mutex.Lock()
	s.resetLocally.Set(true)
	s.ctxCancel()
	// errors must not be changed!
	if s.err == nil {
		s.err = err
		s.signalRead()
		s.signalWrite()
	}
	if s.shouldSendReset() {
		s.onReset(s.streamID, s.writeOffset)
		s.rstSent.Set(true)
	}
	s.mutex.Unlock()
}

// resets the stream remotely
func (s *stream) RegisterRemoteError(err error) {
	if s.resetRemotely.Get() {
		return
	}
	s.mutex.Lock()
	s.resetRemotely.Set(true)
	s.ctxCancel()
	// errors must not be changed!
	if s.err == nil {
		s.err = err
		s.signalWrite()
	}
	if s.shouldSendReset() {
		s.onReset(s.streamID, s.writeOffset)
		s.rstSent.Set(true)
	}
	s.mutex.Unlock()
}

func (s *stream) finishedWriteAndSentFin() bool {
	return s.finishedWriting.Get() && s.finSent.Get()
}

func (s *stream) finished() bool {
	return s.cancelled.Get() ||
		(s.finishedReading.Get() && s.finishedWriteAndSentFin()) ||
		(s.resetRemotely.Get() && s.rstSent.Get()) ||
		(s.finishedReading.Get() && s.rstSent.Get()) ||
		(s.finishedWriteAndSentFin() && s.resetRemotely.Get())
}

func (s *stream) Context() context.Context {
	return s.ctx
}

func (s *stream) StreamID() protocol.StreamID {
	return s.streamID
}

func (s *stream) GetBytesSent() (protocol.ByteCount, error) {
 	return s.flowControlManager.GetBytesSent(s.streamID)
}

 func (s *stream) GetBytesRetrans() (protocol.ByteCount, error) {
 	return s.flowControlManager.GetBytesRetrans(s.streamID)
}

