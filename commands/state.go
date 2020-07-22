package commands

import (
	"errors"
	"github.com/chris-wood/odoh"
	"net/http"
	"sync"
	"time"
)

type state struct {
	sync.RWMutex
	publicKeyState map[string]odoh.ObliviousDNSPublicKey
	client *http.Client
}

var instance state

func GetInstance() *state {
	tr := &http.Transport{
		MaxIdleConnsPerHost: 1024,
		TLSHandshakeTimeout: 0 * time.Second,
	}
	instance.client = &http.Client{Transport: tr}
	instance.publicKeyState = make(map[string]odoh.ObliviousDNSPublicKey)
	return &instance
}

func (s *state) InsertKey(targethost string, key odoh.ObliviousDNSPublicKey) {
	s.Lock()
	defer s.Unlock()
	s.publicKeyState[targethost] = key
}

func (s *state) GetPublicKey(targethost string) (odoh.ObliviousDNSPublicKey, error) {
	s.RLock()
	defer s.RUnlock()
	if key, ok := s.publicKeyState[targethost]; ok {
		return key, nil
	}
	return odoh.ObliviousDNSPublicKey{}, errors.New("public key for target not available")
}

func (s *state) TotalNumberOfTargets() int {
	s.RLock()
	defer s.RUnlock()
	return len(s.publicKeyState)
}