package type2

import "time"

func ReslovePadding(b []byte, salt []byte, key []byte) ([]byte, error) {
	var hash = hmacSha256(key, salt)
	var length = paddingLength(hash)
	if len(b) < length {
		return nil, ErrInvalidPadding
	}
	var padding = b[:length]
	if !testPadding(hash, padding) {
		return nil, ErrInvalidPadding
	}
	return padding, nil
}

func GetPadding(salt []byte, key []byte) []byte {
	var hash = hmacSha256(key, salt)
	var length = paddingLength(hash)
	return hash[0:length]
}

func ResloveTimestamp(b []byte) (int64, error) {
	if len(b) < 4 {
		return 0, ErrInvalidTimestamp
	}
	var timestamp = bytesToU32(b[:4])
	if !testTimestamp(timestamp) {
		return 0, ErrInvalidTimestamp
	}
	return timestamp, nil
}

func GetTimestamp() []byte {
	var timestamp = time.Now().Unix()
	return u32ToBytes(timestamp)
}
