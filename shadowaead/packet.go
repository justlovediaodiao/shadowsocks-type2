package shadowaead

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/justlovediaodiao/shadowsocks-type2/internal"
	"github.com/justlovediaodiao/shadowsocks-type2/type2"
)

// ErrShortPacket means that the packet is too short for a valid encrypted packet.
var ErrShortPacket = errors.New("short packet")

var _zerononce [128]byte // read-only. 128 bytes is more than enough.

// Pack encrypts plaintext using Cipher with a randomly generated salt and
// returns a slice of dst containing the encrypted packet and any error occurred.
// Ensure len(dst) >= ciph.SaltSize() + len(plaintext) + aead.Overhead().
func Pack(dst, plaintext []byte, ciph Cipher) ([]byte, error) {
	saltSize := ciph.SaltSize()
	salt := dst[:saltSize]
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	aead, err := ciph.Encrypter(salt)
	if err != nil {
		return nil, err
	}
	var padding = type2.GetPadding(salt, ciph.Key())
	var paddingSize = len(padding)
	copy(dst[saltSize:], padding)

	internal.AddSalt(salt)

	var timestamp = type2.GetTimestamp()
	copy(dst[saltSize+paddingSize:], timestamp)
	if len(dst) < saltSize+paddingSize+len(timestamp)+len(plaintext)+aead.Overhead() {
		return nil, io.ErrShortBuffer
	}
	copy(dst[saltSize+paddingSize+len(timestamp):], plaintext)
	plaintext = dst[saltSize+paddingSize : saltSize+paddingSize+len(timestamp)+len(plaintext)]

	b := aead.Seal(dst[saltSize+paddingSize:saltSize+paddingSize], _zerononce[:aead.NonceSize()], plaintext, nil)
	return dst[:saltSize+paddingSize+len(b)], nil
}

// Unpack decrypts pkt using Cipher and returns a slice of dst containing the decrypted payload and any error occurred.
// Ensure len(dst) >= len(pkt) - aead.SaltSize() - aead.Overhead().
func Unpack(dst, pkt []byte, ciph Cipher) ([]byte, error) {
	saltSize := ciph.SaltSize()
	if len(pkt) < saltSize {
		return nil, ErrShortPacket
	}
	salt := pkt[:saltSize]
	padding, err := type2.ReslovePadding(pkt[saltSize:], salt, ciph.Key())
	if err != nil {
		return nil, err
	}
	var paddingSize = len(padding)

	if internal.CheckSalt(salt) {
		return nil, ErrRepeatedSalt
	}
	aead, err := ciph.Decrypter(salt)
	if err != nil {
		return nil, err
	}

	if len(pkt) < saltSize+paddingSize+aead.Overhead() {
		return nil, ErrShortPacket
	}
	if saltSize+paddingSize+len(dst)+aead.Overhead() < len(pkt) {
		return nil, io.ErrShortBuffer
	}
	b, err := aead.Open(dst[saltSize+paddingSize:saltSize+paddingSize], _zerononce[:aead.NonceSize()], pkt[saltSize+paddingSize:], nil)
	_, err = type2.ResloveTimestamp(b)
	if err != nil {
		return nil, err
	}
	return b[4:], err
}

type packetConn struct {
	net.PacketConn
	Cipher
	sync.Mutex
	buf []byte // write lock
}

// NewPacketConn wraps a net.PacketConn with cipher
func NewPacketConn(c net.PacketConn, ciph Cipher) net.PacketConn {
	const maxPacketSize = 64 * 1024
	return &packetConn{PacketConn: c, Cipher: ciph, buf: make([]byte, maxPacketSize)}
}

// WriteTo encrypts b and write to addr using the embedded PacketConn.
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.Lock()
	defer c.Unlock()
	buf, err := Pack(c.buf, b, c)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(buf, addr)
	return len(b), err
}

// ReadFrom reads from the embedded PacketConn and decrypts into b.
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	bb, err := Unpack(b, b[:n], c)
	if err != nil {
		return n, addr, err
	}
	copy(b, bb)
	return len(bb), addr, err
}
