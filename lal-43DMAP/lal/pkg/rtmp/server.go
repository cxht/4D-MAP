// Copyright 2019, Chef.  All rights reserved.
// https://github.com/q191201771/lal
//
// Use of this source code is governed by a MIT-style license
// that can be found in the License file.
//
// Author: Chef (191201771@qq.com)

package rtmp

import (
	"net"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	//"encoding/binary"
	"encoding/pem"
	//"fmt"
	"math/big"
	quic "github.com/lucas-clemente/quic-go"
	log "github.com/q191201771/naza/pkg/nazalog"
)

type ServerObserver interface {
	OnRTMPConnect(session *ServerSession, opa ObjectPairArray)
	OnNewRTMPPubSession(session *ServerSession) bool // 返回true则允许推流，返回false则强制关闭这个连接
	OnDelRTMPPubSession(session *ServerSession)
	OnNewRTMPSubSession(session *ServerSession) bool // 返回true则允许拉流，返回false则强制关闭这个连接
	OnDelRTMPSubSession(session *ServerSession)
}

type Server struct {
	observer ServerObserver
	addr     string
	lnau	net.Listener
	lntcp       net.Listener
	ln	quic.Listener
	conn quic.Stream
	protocol string
	hasau	bool
}

func NewServer(observer ServerObserver, addr string, protocol string, hasau bool) *Server {
	return &Server{
		observer: observer,
		addr:     addr,
		protocol:	protocol,
		hasau: hasau,
	}
}

func (server *Server) Listen() (err error) {
	//if ; err != nil {
	quicConfig := &quic.Config{
			CreatePaths: true,
	}
	log.Infof("hasau %v",server.hasau)
	if server.protocol == "quic"{
		server.ln , err  = quic.ListenAddr(server.addr, generateTLSConfig(), quicConfig)
		log.Infof("start rtmp server listen. addr=%s  proto:%s", server.addr,server.protocol)
	}

	if( server.protocol == "tcp"){
		log.Infof("hahahahhahahaha")
		server.lntcp, err = net.Listen("tcp", server.addr)
		log.Infof("start rtmp server listen. ,lntcp = %v, addr=%s  proto:%s, err:%v", server.lntcp, server.addr,server.protocol,err)
	}
	
	
	return
}


func (server *Server) ListenAU() (err error) {
	//if ; err != nil {
	if(server.protocol == "tcp"){
		server.lnau, err = net.Listen("tcp", "0.0.0.0:1936")
		log.Infof("start rtmp server listen. ln=%s	addr=%s  proto:%s AU", server.lnau,server.addr,server.protocol)
	}else{
		server.lntcp, err = net.Listen("tcp",server.addr)
		log.Infof("start rtmp server listen. ln=%s	addr=%s  proto:%s AU", server.lntcp,server.addr,server.protocol)
	}

	return
}
func (server *Server) RunLoop() error {
	for {
		if server.protocol == "tcp"{
			conn, err := server.lntcp.Accept()
			if err != nil {
				return err
			}
			go server.handleTCPConnectTCP(conn)
		}else{
			sess,err := server.ln.Accept()
			conn,err := sess.AcceptStream()
			if err != nil {
				return err
			}
			go server.handleTCPConnect(conn)
		}


	}
}

func (server *Server) RunLoopAU() error {
	//for {
		if(server.protocol == "tcp"){
			conn, err := server.lnau.Accept()
			if err != nil {
				return err
			}
			go server.handleTCPConnectTCP(conn)
			
		}else{
			conn, err := server.lntcp.Accept()
			if err != nil {
				return err
			}
			go server.handleTCPConnectTCP(conn)

		}
		
		log.Infof("conn has been accpeted")
		return nil
	//}
}

func (server *Server) Dispose() {
	if server.ln == nil || server.lntcp == nil{
		return
	}
	if server.protocol =="tcp"{
		if err := server.lntcp.Close(); err != nil {
			log.Error(err)
		}
	}else{
		if err := server.ln.Close(); err != nil {
			log.Error(err)
		}
	}

}

//func (server *Server) handleTCPConnect(conn net.Conn) {
func (server *Server) handleTCPConnect(conn quic.Stream) {
	//log.Infof("accept a rtmp connection. remoteAddr=%s", conn.RemoteAddr().String())
	session := NewServerSession(server, conn)
	err := session.RunLoop()
	log.Infof("[%s] rtmp loop done. err=%v", session.uniqueKey, err)
	switch session.t {
	case ServerSessionTypeUnknown:
	// noop
	case ServerSessionTypePub:
		server.observer.OnDelRTMPPubSession(session)
	case ServerSessionTypeSub:
		server.observer.OnDelRTMPSubSession(session)
	}
}

func (server *Server) handleTCPConnectTCP(conn net.Conn) {
	//log.Infof("accept a rtmp connection. remoteAddr=%s", conn.RemoteAddr().String())
	session := NewServerSession(server, conn)
	err := session.RunLoop()
	log.Infof("[%s] rtmp loop done. err=%v", session.uniqueKey, err)
	switch session.t {
	case ServerSessionTypeUnknown:
	// noop
	case ServerSessionTypePub:
		server.observer.OnDelRTMPPubSession(session)
	case ServerSessionTypeSub:
		server.observer.OnDelRTMPSubSession(session)
	}
}

// ServerSessionObserver
func (server *Server) OnRTMPConnect(session *ServerSession, opa ObjectPairArray) {
	server.observer.OnRTMPConnect(session, opa)
}

// ServerSessionObserver
func (server *Server) OnNewRTMPPubSession(session *ServerSession) {
	if !server.observer.OnNewRTMPPubSession(session) {
		log.Warnf("dispose PubSession since pub exist.")
		session.Dispose()
		return
	}
}

// ServerSessionObserver
func (server *Server) OnNewRTMPSubSession(session *ServerSession) {
	if !server.observer.OnNewRTMPSubSession(session) {
		session.Dispose()
		return
	}
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
