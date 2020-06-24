package commands

import (
	"fmt"
	"github.com/chris-wood/dns"
	"github.com/chris-wood/odoh"
	"log"
)

// Function for Converting CLI DNS Query Type to the uint16 Datatype
func dnsQueryStringToType(stringType string) uint16 {
	switch stringType {
	case "A":
		return dns.TypeA
	case "AAAA":
		return dns.TypeAAAA
	case "CAA":
		return dns.TypeCAA
	case "CNAME":
		return dns.TypeCNAME
	default:
		return 0
	}
}

func parseDnsResponse(data []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(data)
	return msg, err
}

func prepareDnsQuestion(domain string, questionType uint16) (res []byte) {
	dnsMessage := new(dns.Msg)
	dnsMessage.SetQuestion(domain, questionType)
	dnsSerializedString, err := dnsMessage.Pack()
	if err != nil {
		log.Fatalf("Unable to Pack the dnsMessage correctly %v", err)
	}
	return dnsSerializedString
}

func prepareOdohQuestion(domain string, questionType uint16, key []byte) (res []byte) {
	dnsMessage := prepareDnsQuestion(domain, questionType)
	fmt.Println(dnsMessage)
	odohQuery := odoh.ObliviousDNSQuery{
		ResponseKey: key,
		DnsMessage:  dnsMessage,
	}
	// TODO: This needs more work around the actual Encryption necessary
	message := odoh.ObliviousDNSMessage{
		MessageType:      odoh.QueryType,
		KeyID:            key,
		EncryptedMessage: odohQuery.Marshal(),
	}
	fmt.Printf("[ODOH Message] %v\n", message)
	return odohQuery.Marshal()
}