package main

import (
	"crypto/tls"
	"time"
	//"os"

	"fmt"
	"net"

	"github.com/lucas-clemente/quic-go"
	"github.com/q191201771/lal/pkg/remux"

	"github.com/q191201771/lal/pkg/base"

	"github.com/q191201771/lal/pkg/httpflv"
	"github.com/q191201771/lal/pkg/rtmp"
	"github.com/q191201771/naza/pkg/nazalog"
)



func initLog() {
	_ = nazalog.Init(func(option *nazalog.Option) {
		option.AssertBehavior = nazalog.AssertFatal
	})
}

func rtmpOverQUIC(network, local, addr, rawurl string,
	tlsCfg *tls.Config, cfg *quic.Config,
	//cfg *quic.Config,
	filename string, rtmpType bool, protocol string) {
	initLog()
	defer nazalog.Sync()
	var session quic.Session
	nazalog.Debugf("protocol = %s",protocol)
	if protocol == "tcp" {

		rtmp.DialTCP = net.Dial
	} else {
		//var session quic.Session
		fmt.Println(local)
		rtmp.Dial = dial(local, &tls.Config{InsecureSkipVerify: true}, cfg, session)
		nazalog.Debugf("[monitor]sess :%v", session)
	}
	rtmp.Network = network

	defer func() {
		var err error
		if session != nil {
			session.Close(err)
			//session.Close()
		}
	}()

	if rtmpType {
		pullrtmp(rawurl, filename)
		return
	}

	//pushrtmp("rtmp://1.116.187.145:1935/live/", filename)
	pushrtmp(rawurl, filename, protocol)
}

func pullrtmp(url, filename string) {
	var (
		w   httpflv.FLVFileWriter
		err error
	)
	err = w.Open(filename)
	nazalog.Assert(nil, err)
	defer w.Dispose()
	err = w.WriteRaw(httpflv.FLVHeader)
	nazalog.Assert(nil, err)

	session := rtmp.NewPullSession(func(option *rtmp.PullSessionOption) {
		//option.PullTimeoutMS = 10000
		//option.ReadAVTimeoutMS = 10000
	})

	err = session.Pull(url, func(msg base.RTMPMsg) {
		tag := remux.RTMPMsg2FLVTag(msg)
		err := w.WriteTag(*tag)
		nazalog.Assert(nil, err)
	})

	if err != nil {
		nazalog.Errorf("pull failed. err=%+v", err)
		return
	}

	err = <-session.WaitChan()
	nazalog.Debugf("< session.WaitChan. [%s] err=%+v", session.UniqueKey(), err)
}

func pushrtmp(url, filename string, protocol string) {
	tags, err := httpflv.ReadAllTagsFromFLVFile(filename) //read flv file
	t := float64(time.Now().UnixNano()/1000000)
	now := float64(time.Now().UnixNano()/1000000)
	if err != nil || len(tags) == 0 {
		nazalog.Fatalf("read tags from flv file failed. err=%+v", err)
	}
	nazalog.Infof("read tags from flv file succ. len of tags=%d", len(tags))

	session := rtmp.NewPushSession(protocol, func(option *rtmp.PushSessionOption) {
		//option.PushTimeoutMS = 5000
		//option.WriteAVTimeoutMS = 10000
	})

	if err := session.Push(url); err != nil {
		nazalog.Errorf("push failed. err=%v", err)
		return
	}
	now = float64(time.Now().UnixNano() / 1000000)
	
	nazalog.Infof("push succ. url=%s, handshaketime:%f,", url,now - t )

	loopPush(tags, session)
}

func loopPush(tags []httpflv.Tag, session *rtmp.PushSession) {
	var (
		totalBaseTS        uint32 // 每轮最后更新
		prevTS             uint32 // 上一个tag
		hasReadThisBaseTS  bool
		thisBaseTS         uint32 // 每轮第一个tag
		hasTraceFirstTagTS bool
		firstTagTS         uint32 // 所有轮第一个tag
		firstTagTick       int64  // 所有轮第一个tag的物理发送时间
		lastTagTick			int64 //cx add for checking fps
		i int64
		//tagtype string
		iskey string
		keyframesum int
		key_num int
		unkeyframesum int
		unkey_num int
		audiosum int
		audio_num int

		unkeybehindlastI int
		thrownum	int

		meanISize float64
		meanGOPSize float64

		curgop int
		curI  int

		//setcwndflag bool
	)

	// 1. 保证metadata只在最初发送一次
	// 2. 多轮，时间戳会翻转，需要处理，让它线性增长


	// 多轮，一个循环代表一次完整文件的发送, cx tag: repeat play is not allowed
	//for {

		hasReadThisBaseTS = false

		// 一轮，遍历文件的所有tag数据
		//nazalog.Warnf("len:%d",len(tags))
		//time.Sleep(9800000000)
		for _, tag := range tags {
			h := remux.FLVTagHeader2RTMPHeader(tag.Header)
			//nazalog.Debugf("msg :%v",h)
			// metadata只发送一次
			if tag.IsMetadata() {
				if totalBaseTS == 0 {
					h.TimestampAbs = 0
					chunks := rtmp.Message2Chunks(tag.Raw[11:11+h.MsgLen], &h, false)
					if err := session.Write(chunks); err != nil {
						nazalog.Errorf("write data error. err=%v", err)
						return
					}
				}
				continue
			}

			if hasReadThisBaseTS {
				// 本轮非第一个tag
				// 之前已经读到了这轮读文件的base值，ts要减去base
				h.TimestampAbs = tag.Header.Timestamp - thisBaseTS + totalBaseTS
			} else {
				// 本轮第一个tag

				// 设置base，ts设置为上一轮读文件的值
				thisBaseTS = tag.Header.Timestamp
				h.TimestampAbs = totalBaseTS
				hasReadThisBaseTS = true
			}

			if h.TimestampAbs < prevTS {
				// ts比上一个包的还小，直接设置为上一包的值，并且不sleep直接发送
				h.TimestampAbs = prevTS
				nazalog.Errorf("this tag timestamp less than prev timestamp. h.TimestampAbs=%d, prevTS=%d", h.TimestampAbs, prevTS)
			}
			var mark bool
			
			if((unkeybehindlastI < 104) && unkeybehindlastI > 90 && (key_num == 3)) || ((unkeybehindlastI < 104) && unkeybehindlastI > 95 && (key_num == 4)) {
				mark = false
			}else{
				mark = false
			}
			chunks := rtmp.Message2Chunks(tag.Raw[11:11+h.MsgLen], &h, mark)
			i+=1 
			if hasTraceFirstTagTS {
				// 所有轮的非第一个tag

				// 当前距离第一个tag的物理发送时间，以及距离第一个tag的时间戳
				// 如果物理时间短，就睡眠相应的时间
				n := time.Now().UnixNano() / 1000000

				diffTick := n - firstTagTick
				diffTS := h.TimestampAbs - firstTagTS
				
				if tag.Header.Type ==  httpflv.TagTypeVideo{
					gapTick := n - lastTagTick
					nazalog.Debugf("\nchunk:%v chunk-dur:%vms, timestamp:%v",key_num+unkey_num,gapTick,  tag.Header.Timestamp)
					lastTagTick = n
				}

				if diffTick < int64(diffTS) {
					//time.Sleep(time.Duration(int64(diffTS)-diffTick) * time.Millisecond)
					time.Sleep((time.Duration(int64(diffTS)-diffTick) )* time.Millisecond)
				}
				//time.Sleep(80* time.Millisecond)
			} else {
				// 所有轮的第一个tag
				nazalog.Debugf("Livestreaming start sending tick:%v", time.Now().UnixNano()/ 1000)
				// 记录所有轮的第一个tag的物理发送时间，以及数据的时间戳
				firstTagTick = time.Now().UnixNano() / 1000000
				firstTagTS = h.TimestampAbs
				lastTagTick = firstTagTick
				hasTraceFirstTagTS = true
			}

			/* cx add : normal proccess. differientiate frame types for statistic and delim*/
			//nazalog.Infof("write size : %v",len(chunks))

			iskey = " "
			
			// flag, limit := session.ReturnMonitor()
			// sch := session.ReturnSchName()
			flag := false
			limit := 0
			sch := ""
			nazalog.Debugf("Return monitor from  scheduler : %v, bw flag : %v, limit : %v",sch,flag, limit)
			curframesize := len(chunks)
			if tag.Header.Type == httpflv.TagTypeMetadata{
				//tagtype = "meta"
				nazalog.Debugf("META DATA!")
				// if err := session.Write(chunks); err != nil {
				// 	nazalog.Errorf("write META error. err=%v", err)
				// 	return
				// }
			}else if tag.Header.Type ==  httpflv.TagTypeVideo{
				if tag.IsVideoKeyNALU(){
					iskey = "key tag"
					//compute mean value
					if(key_num != 0){
						meanGOPSize = float64( (keyframesum + unkeyframesum) / key_num )
						meanISize = float64( keyframesum / key_num)
					}
					
					keyframesum += curframesize
					key_num += 1
					fmt.Println(iskey,len(chunks))
					unkeybehindlastI = 0
					curgop = curframesize
					curI = curframesize

					
					nazalog.Debugf("%v I frame %v", key_num, curframesize)
				} else{
					unkeyframesum += curframesize
					curgop += curframesize
					unkey_num += 1
					unkeybehindlastI += 1
					resideSizeInGOP := meanGOPSize - float64(curgop)
					IFrameisComing := (float64(curI) >= meanISize && resideSizeInGOP < 0) || (float64(curI) < meanISize && resideSizeInGOP < (meanISize - float64(curI)))
					nazalog.Infof("IframeComing %v, resideSizeInGOP %v, meanGOP %v, meanI %v, curgop %v, curI %v",IFrameisComing,resideSizeInGOP, meanGOPSize, meanISize, curgop, curI)
					nazalog.Infof("UNKEYBEHIND %v,limit:%v",unkeybehindlastI,limit)
					

					if flag == true && (((sch == "moooko") && IFrameisComing && curframesize <= 7500 && key_num > 10) || ((sch == "moooko") &&curframesize <= 1800 && key_num > 15)){ // BBB
					//if flag == true && (((sch == "moooko") && IFrameisComing && curframesize <= 7000) || ((sch == "moooko") && curframesize <= 2500)){	
						thrownum += 1
						//nazalog.Infof("\n\n\nthrow %v th p frame: %v, size: %v, \n\n\n\n",thrownum, unkeybehindlastI, len(chunks))
						limit -= len(chunks)
						//continue
					}
					nazalog.Debugf("%v p frame %v", unkeybehindlastI, len(chunks))
				}
				//tagtype = "video"
			}else if tag.Header.Type == httpflv.TagTypeAudio{
				//tagtype = "audio"
				audiosum += len(chunks)
				audio_num += 1
				nazalog.Debugf("a frame %v", len(chunks))

			}else{
				//tagtype = "else"
				/*
				if err := session.Write(chunks); err != nil {
					nazalog.Errorf("write A_FRAME error. err=%v", err)
					return
				}*/
				nazalog.Debugf("WHAT?")
			}
			//nazalog.Debugf(tagtype+iskey+" tag is splited into chunks\n",tag.Header.DataSize,len(tag.Raw),(len(chunks)))
			//nazalog.Debugf(" %v\n",chunks)
			// if tag.Header.Timestamp == 39433{
			// 	nazalog.Debugf("closecwnd = true")
			// 	session.SetCWNDFlag(true)
			// 	setcwndflag = true
			// }else if (tag.Header.Timestamp >= 39467 && setcwndflag == true){
			// 	nazalog.Debugf("closecwnd = false")
			// 	session.SetCWNDFlag(false)
			// 	setcwndflag=false
			// }

			if err := session.Write(chunks); err != nil {
				nazalog.Errorf("write  chunks error. err=%v", err)
				return
			}
			//nazalog.Debugf("write len %v",len(chunks))
			// if(tagtype == "video"&&  iskey =="key tag" ){
			// 	os.Exit(-1)
			// }
			
			//cx add: for debugging
			/*
			//if(tagtype == "video" && iskey == "key tag"){
			if(tagtype == "video" ){
				if(iskey == "key tag"){								//cx for debug: video i tag: byte 0-255
					time.Sleep(9800000000)
					// for i:=0 ; i < len(chunks) ; i++{
					// 	chunks[i] = byte(0)
					// }
					if err := session.Write(chunks); err != nil {
						nazalog.Errorf("write data error. err=%v", err)
					 	return
					 }
					time.Sleep(9800000000)
					os.Exit(1)
				}else{
					for i:=0 ; i < len(chunks) ; i++{		//cx for debug: video p tag byte 00000
						chunks[i] = byte(iter%255)
					}
					if err := session.Write(chunks); err != nil {
						nazalog.Errorf("write data error. err=%v", err)
						return
					}
				}
				
				//time.Sleep(9800000000)
				
			}else{
				if err := session.Write(chunks); err != nil {
					nazalog.Errorf("write data error. err=%v", err)
					return
				}
				
			}
		//}*/
			iskey = " "

			prevTS = h.TimestampAbs
		} // tags for loop
		nazalog.Infof("mean key frame size : %d, num: %d \n mean p frame size : %d , num : %d\n", keyframesum/key_num, key_num, unkeyframesum/unkey_num, unkey_num)
		totalBaseTS = prevTS + 1

		
		time.Sleep(1000000* time.Millisecond)
		
	//}
}
