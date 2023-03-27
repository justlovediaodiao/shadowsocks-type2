package http

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/justlovediaodiao/shadowsocks-type2/socks"
)

// http status code and description.
const (
	http200 = "200 OK"
	http400 = "400 Bad Request"
)

// Conn turn http proxy request to stream
type Conn struct {
	net.Conn
	r io.ReadCloser // pipe http request to reader
}

// httpResponse write http response to client
func httpResponse(conn net.Conn, status string) error {
	var line = fmt.Sprintf("HTTP/1.1 %s\r\n\r\n", status)
	_, err := conn.Write([]byte(line))
	return err
}

// joinHostPort join port to host if host contains no port
func joinHostPort(host string, port string) string {
	if strings.LastIndexByte(host, ':') == -1 || strings.HasSuffix(host, "]") { // ipv6 addr [...]
		return fmt.Sprintf("%s:%s", host, port)
	}
	return host
}

// Handshake do proxy side http handshake to app.
// Return target address that app want to connect to.
func Handshake(conn net.Conn) (socks.Addr, net.Conn, error) {
	var bufConn = bufio.NewReader(conn)
	req, err := http.ReadRequest(bufConn)
	if err != nil {
		return nil, nil, err
	}
	var host = joinHostPort(req.URL.Host, "80")
	var addr = socks.ParseAddr(host)
	if req.Method == "CONNECT" { // tunnel mode, for https. just relay after handshake
		req.Body.Close()
		if addr == nil {
			httpResponse(conn, http400)
			return nil, nil, errors.New(http400)
		}
		if err = httpResponse(conn, http200); err != nil {
			return nil, nil, err
		}
		return addr, nil, nil
	}
	// proxy mode, for http. forward http request to remote.
	if addr == nil {
		return nil, nil, errors.New(http400)
	}
	var c = &Conn{conn, http2Tunnel(req, bufConn)}
	return addr, c, err
}

func http2Tunnel(req *http.Request, bufConn *bufio.Reader) io.ReadCloser {
	r, w := io.Pipe()
	go func() {
		for {
			err := req.Write(w)
			if err != nil {
				w.CloseWithError(err)
				break
			}
			req, err = http.ReadRequest(bufConn)
			if err != nil {
				w.CloseWithError(err)
				break
			}
		}
	}()
	return r
}

// Read reads data from connection.
func (c *Conn) Read(b []byte) (int, error) {
	if c.r != nil {
		return c.r.Read(b)
	}
	return c.Conn.Read(b)
}

// Close close connection.
func (c *Conn) Close() error {
	if c.r != nil {
		c.r.Close()
	}
	return c.Conn.Close()
}
