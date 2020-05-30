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
	bufConn *bufio.Reader // used to read net.Conn for http
	request io.Reader     // http request used to forward to remote
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
	if req.Method == "CONNECT" { // tunnel mode, for https. just relay after handshake
		req.Body.Close()
		var host = joinHostPort(req.URL.Host, "80")
		var addr = socks.ParseAddr(host)
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
	var host = joinHostPort(req.URL.Host, "80")
	var addr = socks.ParseAddr(host)
	if addr == nil {
		return nil, nil, errors.New(http400)
	}
	var c = &Conn{conn, bufConn, newRequestReader(req)}
	return addr, c, err
}

// Read reads data from the connection.
func (c *Conn) Read(b []byte) (int, error) {
READ:
	if c.request == nil {
		req, err := http.ReadRequest(c.bufConn)
		if err != nil {
			return 0, err
		}
		c.request = newRequestReader(req)
	}
	n, err := c.request.Read(b)
	if err == io.EOF { // EOF, request ended
		c.request = nil
		err = nil
		goto READ
	}
	return n, err
}

// requestReader trun http.Request to stream used to forward to remote.
// Read call will automatically close req.Body when read to EOF or error.
type requestReader struct {
	req       *http.Request
	reqReader io.Reader
	eof       bool
}

// Read read data as much as possiable until full or EOF or error.
func (r *requestReader) Read(b []byte) (n int, err error) {
	if r.eof {
		err = io.EOF
		return
	}
	for n < len(b) && err == nil {
		var nn int
		nn, err = r.reqReader.Read(b[n:])
		n += nn
	}
	if err != nil {
		r.req.Body.Close() // must close req.Body
	}
	if n > 0 && err == io.EOF { // should not return eof if n > 0
		r.eof = true
		err = nil
	}
	return
}

// newRequestReader return requestReader.
func newRequestReader(req *http.Request) io.Reader {
	var rs = make([]io.Reader, 0, len(req.Header)+3) // request line + header lines + \r\n + body. assume each header appears once.
	var reqLine = fmt.Sprintf("%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	rs = append(rs, strings.NewReader(reqLine))
	for k, vs := range req.Header {
		// remove hop-by-hop headers, not sure, fuck http specification.
		switch k {
		case "Transfer-Encoding": // request body maybe chuncked, but forwarding to remote is not.
		case "Proxy-Authenticate":
		case "Proxy-Authorization":
		case "Connection":
		case "Trailer":
		case "TE":
		case "Upgrade": // maybe websocket, donot support.
			continue
		case "Proxy-Connection":
			k = "Connection"
		}
		for _, v := range vs {
			var header = fmt.Sprintf("%s: %s\r\n", k, v)
			rs = append(rs, strings.NewReader(header), req.Body)
		}
	}
	// set Host header and \r\n
	rs = append(rs, strings.NewReader(fmt.Sprintf("Host: %s\r\n\r\n", req.Host)))
	return &requestReader{req, io.MultiReader(rs...), false}
}
