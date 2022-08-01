package main

import (
	"crypto/tls"
	//"strings"
	//"fmt"
	"github.com/lucas-clemente/quic-go"
)

func parseCfg(multi bool, serverName string, insecureSkipVerify bool, sch string, red bool, iprio bool) (*tls.Config, *quic.Config) {
	// var gquicvm = map[string]quic.VersionNumber{
	// 	"39": quic.VersionGQUIC39,
	// 	"43": quic.VersionGQUIC43,
	// 	"44": quic.VersionGQUIC44,
	// }

	// versions := []quic.VersionNumber{}
	// if version != "" {
	// 	vs := strings.Split(version, ",")
	// 	for _, v := range vs {
	// 		if vv, ok := gquicvm[v]; ok {
	// 			versions = append(versions, vv)
	// 		}
	// 	}
	// }
	//fmt.Print("sch:%s",sch)
	return &tls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     insecureSkipVerify,
		SessionTicketsDisabled: true}, &quic.Config{CreatePaths: multi, SchedulerName: sch, GenerateRedundancy: red, IPriority: iprio}
	// NextProtos:             []string{"39", "43", "44"},
	//}, &quic.Config{Versions: versions}

}
