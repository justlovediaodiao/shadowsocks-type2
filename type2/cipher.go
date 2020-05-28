package type2

import (
	"crypto/hmac"
	"crypto/sha256"
)

func hmacSha256(key []byte, salt []byte) []byte {
	var h = hmac.New(sha256.New, key)
	h.Write(salt)
	return h.Sum(nil)
}

func paddingLength(hash []byte) int {
	var mod = 16
	var s = 0
	for _, v := range hash {
		s += int(v&0x0f + v>>4)
	}
	return s%mod + mod
}

func u32ToBytes(value int64) []byte {
	var b = make([]byte, 4)
	for i := 0; i < 4; i++ {
		b[i] = byte((value >> ((3 - i) * 8)) & 0xff)
	}
	return b
}

func bytesToU32(b []byte) int64 {
	var r int64 = 0
	for i, v := range b {
		r += (int64(v) << ((3 - i) * 8))
	}
	return r
}
