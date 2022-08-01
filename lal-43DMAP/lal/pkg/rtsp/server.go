// Copyright 2020, Chef.  All rights reserved.
// https://github.com/q191201771/lal
//
// Use of this source code is governed by a MIT-style license
// that can be found in the License file.
//
// Author: Chef (191201771@qq.com)

package rtsp

import (
	//"net"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	//"encoding/binary"
	"encoding/pem"
	//"fmt"
	"math/big"

	"github.com/q191201771/naza/pkg/nazalog"
	quic "github.com/lucas-clemente/quic-go"
)

type ServerObserver interface {
	// @brief 使得上层有能力管理未进化到Pub、Sub阶段的Session
	OnNewRTSPSessionConnect(session *ServerCommandSession)

	// @brief 注意，对于已经进化到了Pub、Sub阶段的Session，该回调依然会被调用
	OnDelRTSPSession(session *ServerCommandSession)

	///////////////////////////////////////////////////////////////////////////

	// @brief  Announce阶段回调
	// @return 如果返回false，则表示上层要强制关闭这个推流请求
	OnNewRTSPPubSession(session *PubSession) bool

	OnDelRTSPPubSession(session *PubSession)

	///////////////////////////////////////////////////////////////////////////

	// @return 如果返回false，则表示上层要强制关闭这个拉流请求
	// @return sdp
	OnNewRTSPSubSessionDescribe(session *SubSession) (ok bool, sdp []byte)

	// @brief Describe阶段回调
	// @return ok  如果返回false，则表示上层要强制关闭这个拉流请求
	OnNewRTSPSubSessionPlay(session *SubSession) bool

	OnDelRTSPSubSession(session *SubSession)
}

type Server struct {
	addr     string
	observer ServerObserver

	//ln       net.Listener
	ln	quic.Listener
}

func NewServer(addr string, observer ServerObserver) *Server {
	return &Server{
		addr:     addr,
		observer: observer,
	}
}

func (s *Server) Listen() (err error) {
	quicConfig := &quic.Config{
		CreatePaths: true,
	}
	s.ln , err  = quic.ListenAddr(s.addr, generateTLSConfig(), quicConfig)
	//s.ln, err = net.Listen("tcp", s.addr)
	if err != nil {
		return
	}
	nazalog.Infof("start rtsp server listen. addr=%s", s.addr)
	return
}

func (s *Server) RunLoop() error {
	for {
		sess,err := s.ln.Accept()
		//conn, err := server.ln.Accept()
		conn,err := sess.AcceptStream()
		if err != nil {
			return err
		}
		go s.handleTCPConnect(conn)
	}
}

func (s *Server) Dispose() {
	if s.ln == nil {
		return
	}
	if err := s.ln.Close(); err != nil {
		nazalog.Error(err)
	}
}

// ServerCommandSessionObserver
func (s *Server) OnNewRTSPPubSession(session *PubSession) bool {
	return s.observer.OnNewRTSPPubSession(session)
}

// ServerCommandSessionObserver
func (s *Server) OnNewRTSPSubSessionDescribe(session *SubSession) (ok bool, sdp []byte) {
	return s.observer.OnNewRTSPSubSessionDescribe(session)
}

// ServerCommandSessionObserver
func (s *Server) OnNewRTSPSubSessionPlay(session *SubSession) bool {
	return s.observer.OnNewRTSPSubSessionPlay(session)
}

// ServerCommandSessionObserver
func (s *Server) OnDelRTSPPubSession(session *PubSession) {
	s.observer.OnDelRTSPPubSession(session)
}

// ServerCommandSessionObserver
func (s *Server) OnDelRTSPSubSession(session *SubSession) {
	s.observer.OnDelRTSPSubSession(session)
}

//func (s *Server) handleTCPConnect(conn net.Conn) {
func (s *Server) handleTCPConnect(conn quic.Stream) {
	session := NewServerCommandSession(s, conn)
	s.observer.OnNewRTSPSessionConnect(session)

	err := session.RunLoop()
	nazalog.Info(err)

	if session.pubSession != nil {
		s.observer.OnDelRTSPPubSession(session.pubSession)
	} else if session.subSession != nil {
		s.observer.OnDelRTSPSubSession(session.subSession)
	}
	s.observer.OnDelRTSPSession(session)
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
