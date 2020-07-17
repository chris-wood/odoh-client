package main

import (
	"crypto/rand"
	"fmt"
	"github.com/chris-wood/dns"
	"github.com/chris-wood/odoh-client/commands"
	"github.com/cisco/go-hpke"
	"testing"
)

func Test_QuerySample(t *testing.T) {
	kemID := hpke.DHKEM_X25519
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AESGCM128

	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)

	symmetricKey := make([]byte, suite.AEAD.KeySize())
	rand.Read(symmetricKey)

	targetIP := "localhost:8787"
	pk, err := commands.RetrievePublicKey(targetIP)
	if err != nil {
		t.Fatalf("Unable to fetch public key")
	}

	queryBytes, err := commands.PrepareODOHQuestion("www.sudheesh.info.", dns.TypeAAAA,
		symmetricKey, pk)

	queryResponse, err := commands.CreateODOHQueryResponse(queryBytes, targetIP)

	fmt.Printf("Obtained Response: %v", queryResponse)

	dnsResponse, err := commands.ValidateEncryptedResponse(queryResponse, symmetricKey)
	fmt.Printf("Response \n %v", dnsResponse)
}
