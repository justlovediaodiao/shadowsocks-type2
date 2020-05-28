package internal

import "sync"

// A shared instance used for checking salt repeat
var saltfilter = HashFilter{
	m:     make(map[string]int64, mapLen),
	mutex: &sync.RWMutex{},
}

// TestSalt returns true if salt is repeated
func TestSalt(b []byte) bool {
	return saltfilter.Test(b)
}

// AddSalt salt to filter
func AddSalt(b []byte) {
	saltfilter.Add(b)
}
