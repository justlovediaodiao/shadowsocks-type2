package internal

import (
	"encoding/hex"
	"sync"
	"time"
)

const mapLen = 10240

type HashFilter struct {
	m     map[string]int64
	mutex *sync.RWMutex
}

func (r HashFilter) Test(b []byte) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	var v = hex.EncodeToString(b)
	_, ok := r.m[v]
	return ok
}

func (r HashFilter) Add(b []byte) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	var v = hex.EncodeToString(b)
	var timestamp = time.Now().Unix()
	r.m[v] = timestamp
	// clear old key
	if len(r.m) >= mapLen {
		r.clear(timestamp)
	}
}

func (r HashFilter) Check(b []byte) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	var v = hex.EncodeToString(b)
	if _, ok := r.m[v]; ok {
		return true
	}
	var timestamp = time.Now().Unix()
	r.m[v] = timestamp
	// clear old key
	if len(r.m) >= mapLen {
		r.clear(timestamp)
	}
}

func (r HashFilter) clear(timestamp int64) {
	// clear salts from 6 minutes ago, must be longer than timestamp_valid_range * 2
	timestamp -= 360
	var newMap = make(map[string]int64, mapLen)
	for k, v := range r.m {
		if v >= timestamp {
			newMap[k] = v
		}
	}
	r.m = newMap
}
