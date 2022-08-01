package quic

import (
	"net"
	"sync"
)

type connection interface {
	Write([]byte) error
	Read([]byte) (int, net.Addr, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetCurrentRemoteAddr(net.Addr)
}

type conn struct {
	mutex sync.RWMutex

	pconn       *net.UDPConn
	currentAddr net.Addr
	connected   bool
}

var _ connection = &conn{}

func (c *conn) Write(p []byte) error {
	if c.connected {
		_, err := c.pconn.Write(p)
		return err
	}

	_, err := c.pconn.WriteTo(p, c.currentAddr)
	return err
}

func (c *conn) Read(p []byte) (int, net.Addr, error) {
	if c.connected {
		read, err := c.pconn.Read(p)
		return read, c.pconn.RemoteAddr(), err
	}

	return c.pconn.ReadFrom(p)
}

func (c *conn) SetCurrentRemoteAddr(addr net.Addr) {
	c.mutex.Lock()
	c.currentAddr = addr
	c.mutex.Unlock()
}

func (c *conn) LocalAddr() net.Addr {
	return c.pconn.LocalAddr()
}

func (c *conn) RemoteAddr() net.Addr {
	if c.connected {
		return c.pconn.RemoteAddr()
	}

	c.mutex.RLock()
	addr := c.currentAddr
	c.mutex.RUnlock()
	return addr
}

func (c *conn) Close() error {
	return c.pconn.Close()
}
