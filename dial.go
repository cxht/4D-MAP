package main

import (
	//"context"
	"crypto/tls"
	"net"

	"github.com/lucas-clemente/quic-go"
)

func dialFunc(local, remote string) func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.Session, error) {
	return func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.Session, error) {
		if remote != "" {
			addr = remote
		}
		//udpAddr, err := net.ResolveUDPAddr(network, addr)
		// if err != nil {
		// 	return nil, err
		// }

		localAddr, err := net.ResolveUDPAddr(network, local+":0")
		if err != nil {
			localAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		}

		//var pconn *net.UDPConn
		if localAddr.IP.Equal(net.IPv4zero) {
			//pconn, err = net.ListenUDP(network, localAddr)
			if err != nil {
				return nil, err
			}
		} else {
			//pconn, err = net.DialUDP(network, localAddr, udpAddr)
			if err != nil {
				return nil, err
			}
		}

		//session, err := quic.DialWhichContext(context.Background(),pconn, udpAddr, addr,tlsCfg,cfg, true)
		session, err := quic.DialAddr(addr,tlsCfg,cfg)
		
		//

		
		if err != nil {
			return nil, err
		}

		return session, nil
	}
}

func dial(local string, tlsCfg *tls.Config,
	//cfg *quic.Config, outsession quic.Session) func(network, addr string) (net.Conn, error) {
	cfg *quic.Config, outsession quic.Session) func(network, addr string) (quic.Stream, error) {
	//return func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (quic.Stream, error) {
		//udpAddr, err := net.ResolveUDPAddr(network, addr)
		// if err != nil {
		// 	return nil, err
		// }

		localAddr, err := net.ResolveUDPAddr(network, local+":0")
		if err != nil {
			localAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		}

		//var pconn *net.UDPConn
		if localAddr.IP.Equal(net.IPv4zero) {
			//pconn, err = net.ListenUDP(network, localAddr)
			if err != nil {
				return nil, err
			}
		} else {
			//pconn, err = net.DialUDP(network, localAddr, udpAddr)
			if err != nil {
				return nil, err
			}
		}

		//session, err := quic.DialWhichContext(context.Background(),pconn, udpAddr, addr,tlsCfg,cfg, true)
		session, err := quic.DialAddr(addr,tlsCfg,cfg)
		if err != nil {
			return nil, err
		}
		outsession = session
		stream, err := session.OpenStreamSync()
		//stream.SetLocalAddr(localAddr)
		//stream.SetRemoteAddr(addr)
		if err != nil {
			return nil, err
		}

		return stream, nil
	}
}
