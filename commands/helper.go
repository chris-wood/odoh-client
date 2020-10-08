package commands

import (
	"github.com/miekg/dns"
	"github.com/chris-wood/odoh"
	"log"
	"time"
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

func createOdohQuestion(dnsMessage []byte, publicKey odoh.ObliviousDoHConfigContents) (odoh.ObliviousDNSMessage, odoh.QueryContext, error) {
	start := time.Now()
	prepareQuestionTime := time.Since(start)

	odohQuery := odoh.CreateObliviousDNSQuery(dnsMessage, 0)
	odnsMessage, queryContext, err := publicKey.EncryptQuery(odohQuery)
	encryptionTime := time.Since(start)
	if err != nil {
		log.Fatalf("Unable to Encrypt oDoH Question with provided Public Key of Resolver")
		return odoh.ObliviousDNSMessage{}, odoh.QueryContext{}, err
	}

	log.Printf("Time to Prepare DNS Question : [%v]\n", prepareQuestionTime.Milliseconds())
	log.Printf("Time to Encrypt DNS Question : [%v]\n", encryptionTime.Milliseconds())

	return odnsMessage, queryContext, nil
}