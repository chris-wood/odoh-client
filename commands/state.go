package commands

import (
	"errors"
	"fmt"
	"github.com/chris-wood/odoh"
	"golang.org/x/net/proxy"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type state struct {
	sync.RWMutex
	publicKeyState map[string]odoh.ObliviousDNSPublicKey
	baseClient *http.Client
	client []*http.Client
}

var instance state

func GetInstance(N uint64) *state {
	instance.client = make([]*http.Client, N)
	for index := 0; index < int(N); index++ {
		tr := &http.Transport{
			MaxIdleConnsPerHost: 1024,
			TLSHandshakeTimeout: 0 * time.Second,
			DisableKeepAlives: true,
			DisableCompression: true,
			// Uncomment the line below to explicitly disable http/2 in the clients.
			//TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		}
		instance.client[index] = &http.Client{Transport: tr}
	}
	instance.baseClient = &http.Client{Transport: &http.Transport{
		MaxIdleConnsPerHost: 1024,
		TLSHandshakeTimeout: 0 * time.Second,
	}}
	instance.publicKeyState = make(map[string]odoh.ObliviousDNSPublicKey)
	return &instance
}

func UpdateClientsToTorClients(proxyHostName string, proxyPort int) *state {
	torProxyString := fmt.Sprintf("socks5://%s:%d", proxyHostName, proxyPort)
	torProxyURL, err := url.Parse(torProxyString)
	if err != nil {
		log.Fatalln("Unable to parse SOCKS5 Proxy endpoint")
	}
	torDialer, err := proxy.FromURL(torProxyURL, proxy.Direct)
	for index := 0 ; index < len(instance.client); index++ {
		tr := &http.Transport{
			MaxIdleConnsPerHost: 1024,
			TLSHandshakeTimeout: 0 * time.Second,
			Dial: torDialer.Dial,
		}
		instance.client[index] = &http.Client{Transport: tr}
		log.Printf("Creating Tor Client Instance")
	}
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