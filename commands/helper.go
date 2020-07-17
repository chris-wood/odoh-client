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

func ParseDNSResponse(data []byte) (*dns.Msg, error) {
	return parseDnsResponse(data)
}

func parseDnsResponse(data []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(data)
	return msg, err
}

func PrepareDNSQuestion(domain string, questionType uint16) (res []byte) {
	res = prepareDnsQuestion(domain, questionType)
	return res
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

func PrepareODOHQuestion(domain string, questionType uint16, key []byte, publicKey odoh.ObliviousDNSPublicKey) (res []byte, err error) {
	return prepareOdohQuestion(domain, questionType, key, publicKey);
}

func prepareOdohQuestion(domain string, questionType uint16, key []byte, publicKey odoh.ObliviousDNSPublicKey) (res []byte, err error) {
	dnsMessage := prepareDnsQuestion(domain, questionType)
	fmt.Println(dnsMessage)

	odohQuery := odoh.ObliviousDNSQuery{
		ResponseKey: key,
		DnsMessage:  dnsMessage,
	}

	odnsMessage, err := publicKey.EncryptQuery(odohQuery)
	if err != nil {
		log.Fatalf("Unable to Encrypt oDoH Question with provided Public Key of Resolver")
		return nil, err
	}

	return odnsMessage.Marshal(), nil
}