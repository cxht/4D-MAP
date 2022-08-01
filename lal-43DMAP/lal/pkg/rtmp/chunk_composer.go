// Copyright 2019, Chef.  All rights reserved.
// https://github.com/q191201771/lal
//
// Use of this source code is governed by a MIT-style license
// that can be found in the License file.
//
// Author: Chef (191201771@qq.com)

package rtmp

// chunk_composer.go
// @pure
// 读取chunk，并组织chunk，生成message返回给上层

import (
	"io"
	"log"
	"time"
	"github.com/q191201771/lal/pkg/base"
	"github.com/q191201771/naza/pkg/nazalog"
	"github.com/q191201771/naza/pkg/bele"
)

type ChunkComposer struct {
	peerChunkSize uint32
	csid2stream   map[int]*Stream
}

func NewChunkComposer() *ChunkComposer {
	return &ChunkComposer{
		peerChunkSize: defaultChunkSize,
		csid2stream:   make(map[int]*Stream),
	}
}

func (c *ChunkComposer) SetPeerChunkSize(val uint32) {
	c.peerChunkSize = val
}

type OnCompleteMessage func(stream *Stream) error

// @param cb 回调结束后，内存块会被 ChunkComposer 再次使用
func (c *ChunkComposer) RunLoop(reader io.Reader, cb OnCompleteMessage) error {
	var aggregateStream *Stream
	bootstrap := make([]byte, 11)
	absTsFlag := false
	t := float64(time.Now().UnixNano()/1000000)
	now := float64(time.Now().UnixNano()/1000000)
	var count int
	fps := (1.0 / 60.0) * 1000
	od := 0
	rb := 0.0
	fillcnt := 0
	dur := now - t 
	for {
		// 5.3.1.1. Chunk Basic Header
		// 读取fmt和csid
		if _, err := io.ReadAtLeast(reader, bootstrap[:1], 1); err != nil {
			return err
		}
		//nazalog.Debugf("firstbyte:%v",bootstrap[:1])
		fmt := (bootstrap[0] >> 6) & 0x03
		csid := int(bootstrap[0] & 0x3f)

		// csid可能是变长的
		switch csid {
		case 0:
			if _, err := io.ReadAtLeast(reader, bootstrap[:1], 1); err != nil {
				return err
			}
			csid = 64 + int(bootstrap[0])
		case 1:
			if _, err := io.ReadAtLeast(reader, bootstrap[:2], 2); err != nil {
				return err
			}
			csid = 64 + int(bootstrap[0]) + int(bootstrap[1])*256
		default:
			// noop
		}

		stream := c.getOrCreateStream(csid)

		// 5.3.1.2. Chunk Message Header
		// 当前chunk的fmt不同，Message Header包含的字段也不同，是变长
		switch fmt {
		case 0:
			if _, err := io.ReadAtLeast(reader, bootstrap[:11], 11); err != nil {
				return err
			}
			// 包头中为绝对时间戳
			stream.timestamp = bele.BEUint24(bootstrap)
			stream.header.TimestampAbs = stream.timestamp
			absTsFlag = true
			stream.header.MsgLen = bele.BEUint24(bootstrap[3:])
			stream.header.MsgTypeID = bootstrap[6]
			stream.header.MsgStreamID = int(bele.LEUint32(bootstrap[7:]))

			stream.msg.reserve(stream.header.MsgLen)
		case 1:
			if _, err := io.ReadAtLeast(reader, bootstrap[:7], 7); err != nil {
				return err
			}
			// 包头中为相对时间戳
			stream.timestamp = bele.BEUint24(bootstrap)
			//stream.header.TimestampAbs += stream.header.Timestamp
			stream.header.MsgLen = bele.BEUint24(bootstrap[3:])
			stream.header.MsgTypeID = bootstrap[6]

			stream.msg.reserve(stream.header.MsgLen)
		case 2:
			if _, err := io.ReadAtLeast(reader, bootstrap[:3], 3); err != nil {
				return err
			}
			// 包头中为相对时间戳
			stream.timestamp = bele.BEUint24(bootstrap)
			//stream.header.TimestampAbs += stream.header.Timestamp

		case 3:
			// noop
		}
		//nazalog.Debugf("RTMP_CHUNK_COMPOSER chunk.fmt=%d, csid=%d, header=%+v", fmt, csid, stream.header)

		// 5.3.1.3 Extended Timestamp
		// 使用ffmpeg推流时，发现时间戳超过3字节最大值后，即使是fmt3(即包头大小为0)，依然存在ext ts字段
		// 所以这里我将 `==` 的判断改成了 `>=`
		// TODO chef:
		// - 测试其他客户端和ext ts相关的表现
		// - 这部分可能还有问题，需要根据具体的case调整
		//if stream.header.Timestamp == maxTimestampInMessageHeader {
		if stream.timestamp >= maxTimestampInMessageHeader {
			if _, err := io.ReadAtLeast(reader, bootstrap[:4], 4); err != nil {
				return err
			}
			stream.timestamp = bele.BEUint32(bootstrap)
			//nazalog.Debugf("RTMP_CHUNK_COMPOSER ext. extTs=%d", stream.header.Timestamp)
			switch fmt {
			case 0:
				stream.header.TimestampAbs = stream.timestamp
			case 1:
				fallthrough
			case 2:
				stream.header.TimestampAbs = stream.header.TimestampAbs - maxTimestampInMessageHeader + stream.timestamp
			case 3:
				//nazalog.Infof("mid header 199")
				// noop
			}
		}

		var neededSize uint32
		if stream.header.MsgLen <= c.peerChunkSize {
			neededSize = stream.header.MsgLen
		} else {
			neededSize = stream.header.MsgLen - stream.msg.len()
			if neededSize > c.peerChunkSize {
				neededSize = c.peerChunkSize
			}
		}

		// 因为上面已经对整个msg的长度reserve过了，所以这里就不需要reserve了
		//stream.msg.reserve(neededSize)
		//nazalog.Debugf("boostrap : %v",bootstrap)
		////////////////////cx add for discard, first read 4 bytes////////////////////
		if(neededSize >= 4){
			if _, err := io.ReadAtLeast(reader, stream.msg.buf[stream.msg.e:stream.msg.e+4], 4); err != nil {
				return err
			}
			//nazalog.Debugf("first4 : %v, now msglen:%v", stream.msg.buf[stream.msg.e:stream.msg.e+4], stream.msg.len())
			if(stream.msg.buf[stream.msg.e] == byte(97) && stream.msg.buf[stream.msg.e+1]  == byte(98) && stream.msg.buf[stream.msg.e+2]  == byte(99) && stream.msg.buf[stream.msg.e+3]  == byte(100)){
				// first 4 bytes hit the pattern
				nazalog.Debugf("find discard pattern!")
				zeropad := make([]byte,stream.header.MsgLen - 4)
				neededSize = 4 + uint32(len(zeropad))   // is equal to stream.header.MsgLen
				for i:=0 ; i < len(zeropad) ; i++ {		// zero
					zeropad[i] = byte(0)
				}
				stream.msg.buf[stream.msg.e] = byte(39)			//P header
				stream.msg.buf[stream.msg.e + 1] = byte(1)			//P header
				stream.msg.buf[stream.msg.e + 2] = byte(0)			//P header
				stream.msg.buf[stream.msg.e + 3] = byte(0)			//P header
				copy(stream.msg.buf[stream.msg.e + 4: stream.msg.e + 4 + uint32(len(zeropad))], zeropad)			// may bug
				//nazalog.Debugf("MSG LEN:%v, now msglen:%v,  zeropad :%v", stream.header.MsgLen , stream.msg.len(), len(zeropad))
			}else{
				// pattern is hidden in content
				//nazalog.Debugf("neededsize:%v",neededSize)
				//if _, err := io.ReadAtLeast(reader, stream.msg.buf[stream.msg.e + 4 : stream.msg.e + 4 + (neededSize - 4)], int(neededSize - 4)); err != nil {
				n, err := io.ReadAtLeast(reader, stream.msg.buf[stream.msg.e + 4 : stream.msg.e + 4 + (neededSize - 4)], int(neededSize - 4))
				//nazalog.Debugf( "request len : %v", len(stream.msg.buf[stream.msg.e + 4 : stream.msg.e + 4 + (neededSize - 4)]))
				//n, err := reader.Read(stream.msg.buf[stream.msg.e + 4 : stream.msg.e + 4 + (neededSize - 4)])
				if err != nil && uint32(n) < neededSize && stream.msg.buf[ stream.msg.e + 4 + uint32(n) - 4] == byte(97) {
					// pattern here
					//nazalog.Debugf( "err return bytes : %v, last four bytes : %v", n , stream.msg.buf[ stream.msg.e + 4 + uint32(n) - 4 : stream.msg.e + 4 + uint32(n) ])			
					zeropad := make([]byte, stream.header.MsgLen - stream.msg.len() - 4  - uint32(n))
					for i:=0 ; i < len(zeropad) ; i++ {		// zero
						zeropad[i] = byte(0)
					}
					//nazalog.Debugf("MSG LEN:%v, now msglen:%v, return n: %v,  zeropad :%v", stream.header.MsgLen , stream.msg.len(), n, len(zeropad))
					neededSize = 4 +  uint32(n) + uint32(len(zeropad))
					copy(stream.msg.buf[stream.msg.e + 4 + uint32(n)  : stream.msg.e + 4 + uint32(n) + uint32(len(zeropad))], zeropad)			// may bugs
					
					//nazalog.Debugf("neededsize:%v msg.len:%v",neededSize, stream.msg.len())
				}
			}
		}else{
			if _, err := io.ReadAtLeast( reader, stream.msg.buf[ stream.msg.e  : stream.msg.e + neededSize ], int(neededSize)); err != nil {
				// origin code
				return err
			}
		}
		/////////////////////////////////////////////////////////////////////////////////

		stream.msg.produced(neededSize)

		if stream.msg.len() == stream.header.MsgLen {
			// 对端设置了chunk size
			if stream.header.MsgTypeID == base.RTMPTypeIDSetChunkSize {
				val := bele.BEUint32(stream.msg.buf)
				c.SetPeerChunkSize(val)
			}

			stream.header.CSID = csid
			if !absTsFlag {
				// 这么处理相当于取最后一个chunk的时间戳差值，有的协议栈是取的第一个，正常来说都可以
				stream.header.TimestampAbs += stream.timestamp
			}
			absTsFlag = false
			//nazalog.Debugf("RTMP_CHUNK_COMPOSER cb. fmt=%d, csid=%d, header=%+v, ctimestamp=%d, c=%p",
			//	fmt, csid, stream.header, stream.timestamp, c)

			if stream.header.MsgTypeID == base.RTMPTypeIDAggregateMessage {
				
				firstSubMessage := true
				baseTimestamp := uint32(0)

				// 懒初始化
				if aggregateStream == nil {
					aggregateStream = NewStream()
				}
				aggregateStream.header.CSID = stream.header.CSID

				for stream.msg.len() != 0 {
					// 读取sub message的头
					if stream.msg.len() < 11 {
						return ErrRTMP
					}
					aggregateStream.header.MsgTypeID = stream.msg.buf[stream.msg.b]
					stream.msg.consumed(1)
					aggregateStream.header.MsgLen = bele.BEUint24(stream.msg.buf[stream.msg.b:])
					stream.msg.consumed(3)
					aggregateStream.timestamp = bele.BEUint24(stream.msg.buf[stream.msg.b:])
					stream.msg.consumed(3)
					aggregateStream.timestamp += uint32(stream.msg.buf[stream.msg.b]) << 24
					stream.msg.consumed(1)
					aggregateStream.header.MsgStreamID = int(bele.BEUint24(stream.msg.buf[stream.msg.b:]))
					stream.msg.consumed(3)

					// 计算时间戳
					if firstSubMessage {
						baseTimestamp = aggregateStream.timestamp
						firstSubMessage = false
					}
					aggregateStream.header.TimestampAbs = stream.header.TimestampAbs + aggregateStream.timestamp - baseTimestamp

					// message包体
					if stream.msg.len() < aggregateStream.header.MsgLen {
						return ErrRTMP
					}
					aggregateStream.msg.buf = stream.msg.buf[stream.msg.b : stream.msg.b+aggregateStream.header.MsgLen]
					//aggregateStream.msg.b = 0
					aggregateStream.msg.e = aggregateStream.header.MsgLen
					stream.msg.consumed(aggregateStream.header.MsgLen)

					// sub message回调给上层
					if err := cb(aggregateStream); err != nil {
						return err
					}

					// 跳过prev size字段
					if stream.msg.len() < 4 {
						return ErrRTMP
					}
					stream.msg.consumed(4)
				}
			} else {
				
				if err := cb(stream); err != nil {
					return err
				}
				count += 1
				now = float64(time.Now().UnixNano() / 1000000)
				dur = now - t

				if dur > fps{
					od += 1
					rb += (dur - fps)
					fillcnt += int((dur - fps) / fps)  
				} 
				
				t = now 
				nazalog.Debugf("chunk:%v,chunk-dur:%v, timestamp:%v, od:%v",count,dur,stream.timestamp,od)
				//nazalog.Debugf("chunk:%v,chunk-dur:%v, timestamp:%v",count,now - t,stream.timestamp)
				stream.msg.clear()
			}
		}
		if stream.msg.len() > stream.header.MsgLen {
			log.Panicf("stream msg len should not greater than len field in header. stream.msg.len=%d, len.in.header=%d", stream.msg.len(), stream.header.MsgLen)
		}
	}
}

func (c *ChunkComposer) getOrCreateStream(csid int) *Stream {
	stream, exist := c.csid2stream[csid]
	if !exist {
		stream = NewStream()
		c.csid2stream[csid] = stream
	}
	return stream
}

// 临时存放一些rtmp推流case在这，便于理解，以及修改后，回归用
//
// 场景：ffmpeg推送test.flv至lalserver
// 关注点：message超过chunk时，fmt和timestamp的值
//
// ChunkComposer chunk fmt:1 header:{CSID:6 MsgLen:143 Timestamp:40 MsgTypeID:9 MsgStreamID:1 TimestampAbs:520} csid:6 len:143 ts:520
// ChunkComposer chunk fmt:1 header:{CSID:6 MsgLen:4511 Timestamp:40 MsgTypeID:9 MsgStreamID:1 TimestampAbs:560} csid:6 len:4511 ts:560
// ChunkComposer chunk fmt:3 header:{CSID:6 MsgLen:4511 Timestamp:40 MsgTypeID:9 MsgStreamID:1 TimestampAbs:560} csid:6 len:4511 ts:560
// 此处应只给上层返回一次，也即一个message，时间戳应该是560
// ChunkComposer chunk fmt:1 header:{CSID:6 MsgLen:904 Timestamp:40 MsgTypeID:9 MsgStreamID:1 TimestampAbs:600} csid:6 len:904 ts:600
