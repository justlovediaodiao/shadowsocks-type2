package http

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/justlovediaodiao/shadowsocks-type2/socks"
)

// httpReader read http request line from net.Conn
type httpReader struct {
	reader io.Reader
	buf    []byte
	last   byte
	start  int
	end    int
}

// maxLineLen is max http request line length
const maxLineLen = 8192

// line break
const (
	cr byte = 13 // "\r"
	lf byte = 10 // "\n"
)

// http status code and description.
const (
	http200 = "200 OK"
	http400 = "400 Bad Request"
)

// ReadLine read a http request line endswith \r\n
// The return []byte is a slice of inner bufffer of httpReader.
// It may be changed after next ReadLine call.
func (r *httpReader) ReadLine() ([]byte, error) {
	if r.buf == nil {
		r.buf = make([]byte, maxLineLen)
	} else {
		// read from buffer
		for i, v := range r.buf[r.start:r.end] {
			if r.last == cr && v == lf {
				var result = r.buf[r.start : r.start+i+1]
				r.start += i + 1
				r.last = v
				return result, nil
			}
			r.last = v
		}
		// if not line end, copy data to buffer start, then read from io.
		copy(r.buf, r.buf[r.start:r.end])
		r.end = r.end - r.start
		r.start = 0
	}
	for {
		var start = r.end
		n, err := r.reader.Read(r.buf[start:])
		if err != nil {
			return nil, err
		}
		r.end += n
		for i, v := range r.buf[start:r.end] {
			if r.last == cr && v == lf {
				var result = r.buf[r.start : start+i+1]
				r.start = start + i + 1
				r.last = v
				return result, nil
			}
			r.last = v
		}
		if r.end >= maxLineLen {
			return nil, errors.New("over max request line length")
		}
	}
}

// ReadToEnd read lines until an empty line which is \r\n
func (r *httpReader) ReadToEnd() error {
	for {
		line, err := r.ReadLine()
		if err != nil {
			return err
		}
		// \r\n
		if len(line) == 2 {
			return nil
		}
	}
}

// httpResponse write http response to client
func httpResponse(w io.Writer, status string) error {
	var line = fmt.Sprintf("HTTP/1.1 %s\r\n\r\n", status)
	_, err := w.Write([]byte(line))
	return err
}

// Handshake do http tunnel handshake. Return target address to connect.
func Handshake(rw io.ReadWriter) (socks.Addr, error) {
	var r = httpReader{reader: rw}
	b, err := r.ReadLine()
	if err != nil {
		return nil, err
	}
	var arr = strings.Split(string(b), " ")
	if len(arr) != 3 || arr[2] != "HTTP/1.1\r\n" {
		return nil, errors.New(http400)
	}
	// tunnel mode, for https. read full connnect request and response 2xx, then relay.
	if arr[0] != "CONNECT" { // CONNECT github.com:443 HTTP/1.1
		return nil, errors.New(http400)
	}
	var addr = arr[1]
	if strings.IndexByte(arr[1], ':') == -1 || strings.HasSuffix(arr[1], "]") {
		addr = fmt.Sprintf("%s:80", addr)
	}
	if err = r.ReadToEnd(); err != nil {
		return nil, nil
	}
	if err = httpResponse(rw, http200); err != nil {
		return nil, nil
	}
	var socksAddr = socks.ParseAddr(addr)
	if socksAddr == nil {
		return nil, errors.New(http400)
	}
	return socksAddr, nil
}
