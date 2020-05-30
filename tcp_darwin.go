package main

import (
	"net"

	"github.com/justlovediaodiao/shadowsocks-type2/pfutil"
	"github.com/justlovediaodiao/shadowsocks-type2/socks"
)

func redirLocal(addr, server string, shadow func(net.Conn) net.Conn) {
	tcpLocal(addr, server, shadow, func(c net.Conn) (socks.Addr, net.Conn, error) {
		addr, err := natLookup(c)
		return addr, nil, err
	})
}

func redir6Local(addr, server string, shadow func(net.Conn) net.Conn) {
	panic("TCP6 redirect not supported")
}

func natLookup(c net.Conn) (socks.Addr, error) {
	if tc, ok := c.(*net.TCPConn); ok {
		addr, err := pfutil.NatLookup(tc)
		return socks.ParseAddr(addr.String()), err
	}
	panic("not TCP connection")
}
