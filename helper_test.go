package gois

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

func PkgRequests(paths ...string) []*http.Request {
	reqs := make([]*http.Request, len(paths))
	for i, p := range paths {
		r, _ := http.NewRequest("GET", p, http.NewRequest("GET", p, http.NoBody))
		reqs[i] = r
	}
	return reqs
}

func NewListener(reqs ...*http.Request) (*Listener, error) {
	conns := make([]net.Conn, len(reqs))
	for i, r := range reqs {
		c, err := NewConn(r)
		if err != nil {
			return nil, err
		}
		conns[i] = c
	}

	return &Listener{
		Conns: conns,
	}, nil
}

type Listener struct {
	Conns []net.Conn
	index int
}

// Accept waits for and returns the next connection to the listener.
func (l *Listener) Accept() (net.Conn, error) {
	fmt.Println("Accept")
	if l.index >= len(l.Conns) {
		// time.Sleep(time.Minute * 5)
		return nil, errors.New("listener closed")
	}
	c := l.Conns[l.index]
	l.index++
	return c, nil
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *Listener) Close() error {
	return nil
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return nil
}

func (l *Listener) Dump() {
	for _, c := range l.Conns {
		tconn, ok := c.(*Conn)
		if !ok {
			continue
		}

		buff, ok := tconn.resp.(*bytes.Buffer)
		if !ok {
			continue
		}

		fmt.Println(buff.String())
	}
}

func NewConn(r *http.Request) (net.Conn, error) {
	raw, err := httputil.DumpRequest(r, true)
	if err != nil {
		return nil, err
	}

	fmt.Println(string(raw))

	return &Conn{
		req:  bytes.NewReader(raw),
		resp: bytes.NewBuffer(nil),
		tcp:  true,
		addr: "127.0.0.1",
	}, nil
}

type Conn struct {
	req  io.Reader
	resp io.Writer
	tcp  bool
	addr string
}

func (c *Conn) Read(b []byte) (n int, err error) {
	fmt.Println("Read")
	return c.req.Read(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	fmt.Printf("Write [%s]\n", string(b))
	return c.resp.Write(b)
}

func (c *Conn) Close() error {
	return nil
}

func (c *Conn) RemoteAddr() net.Addr {
	return &testaddr{
		tcp:  c.tcp,
		addr: c.addr,
	}
}

// Not implemented for now, just here to make bconn
// look like a net.Conn
func (c *Conn) LocalAddr() net.Addr {
	return &testaddr{
		tcp:  c.tcp,
		addr: c.addr,
	}
}
func (*Conn) SetDeadline(t time.Time) error      { return nil }
func (*Conn) SetReadDeadline(t time.Time) error  { return nil }
func (*Conn) SetWriteDeadline(t time.Time) error { return nil }

type testaddr struct {
	tcp  bool
	addr string
}

func (t *testaddr) Network() string {
	if t.tcp {
		return "tcp"
	}
	return "udp"
}

func (t *testaddr) String() string {
	return t.addr
}
