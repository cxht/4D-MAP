package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"
)

func main() {
	var (
		network     = flag.String("network", "udp4", "network")
		addr        = flag.String("addr", "127.0.0.1", "example: 1.2.3.4:80")
		sni         = flag.String("sni", "", "domain,empty is skip")
		//quicVersion = flag.String("quic-version", "43", "support 39,43,44")
		protocol = flag.String("protocol","quic","use QUIC or TCP to transport")
		multi	= flag.Bool("multi", true, "whether to use multipath protocol")
		sch = flag.String("sch","rr","select MPQUIC scheduler")
		local       = flag.String("bind", "", "bind local ip")
		name        = flag.String("file", "xu.flv", "specify i/o flv file")
		buffer      = flag.Int("buffer", 102400, "buffer size in byte")
		rtmpType    = flag.Bool("type", false, "whether to pull or publish,true is pull")
		skip        = flag.Bool("skip", true, "whether a client verifies the server's certificate chain and host name")
	)

	flag.Parse()
	fmt.Println(*multi,*sch,*name,*rtmpType)
	rawurl := os.Args[len(os.Args)-1]
	//rawurl = "rtmp://127.0.0.1/"
	//*protocol = "tcp"
	filename := *name
	if *name == "d.flv" {
		filename = time.Now().Format("2006-01-02-15-04-05-999-") + *name
	}
	file, err := os.OpenFile(filename,os.O_WRONLY,0666)
	//	os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
	//	0666)
	if err != nil {
		fmt.Println(err)

		return
	}

	defer func() {
		file.Sync()

		stat, _ := file.Stat()
		if stat.Size() == 0 {
			os.Remove(file.Name())
		}

		file.Close()
	}()

	u, err := url.Parse(rawurl)
	if err != nil {
		fmt.Println(rawurl, err)
		return
	}

	if *sni == "" {
		*sni = u.Host
	}

	tlsCfg, cfg := parseCfg(*multi, *sni, *skip, *sch)

	appBuffer := make([]byte, *buffer)

	quit := make(chan os.Signal, 1)
	run(*network,
		*local,
		*addr,
		rawurl,
		filename,
		tlsCfg,
		cfg,
		appBuffer,
		file,
		u,
		*rtmpType,
		*protocol,
		quit)

	//<-quit
}
