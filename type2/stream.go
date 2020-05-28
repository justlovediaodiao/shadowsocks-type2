package type2

import (
	"errors"
	"io"
	"time"
)

// ErrInvalidPadding means invalid padding
var ErrInvalidPadding = errors.New("invalid padding")

// ErrInvalidTimestamp means invalid timestamp
var ErrInvalidTimestamp = errors.New("invalid timestamp")

// ReadPadding read 16~32 byte padding from stream and check whether the padding is valid
func ReadPadding(r io.Reader, salt []byte, key []byte) error {
	var hash = hmacSha256(key, salt)
	var padding = make([]byte, paddingLength(hash))
	if _, err := io.ReadFull(r, padding); err != nil {
		return err
	}
	if !testPadding(hash, padding) {
		return ErrInvalidPadding
	}
	return nil
}

// ReadTimestamp read 4 byte timestamp from stream and check whether the timestamp is valid
func ReadTimestamp(r io.Reader) (int64, error) {
	var b = make([]byte, 4)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, err
	}
	var timestamp = bytesToU32(b)
	if !testTimestamp(timestamp) {
		return 0, ErrInvalidTimestamp
	}
	return timestamp, nil
}

// WritePadding write 16~32 byte padding to stream
func WritePadding(w io.Writer, salt []byte, key []byte) error {
	var hash = hmacSha256(key, salt)
	var length = paddingLength(hash)
	var padding = hash[0:length]
	if _, err := w.Write(padding); err != nil {
		return err
	}
	return nil
}

// WriteTimestamp write 4 byte current timestamp to stream
func WriteTimestamp(w io.Writer) error {
	var timestamp = time.Now().Unix()
	var b = u32ToBytes(timestamp)
	if _, err := w.Write(b); err != nil {
		return err
	}
	return nil
}

func testPadding(hash []byte, padding []byte) bool {
	for i, v := range padding {
		if v != hash[i] {
			return false
		}
	}
	return true
}

func testTimestamp(timestamp int64) bool {
	var diff = time.Now().Unix() - timestamp
	return diff >= -120 && diff <= 120
}
