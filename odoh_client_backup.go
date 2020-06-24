package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net/http"

	// "github.com/miekg/dns"
	"github.com/chris-wood/dns"
)

func vendRecord(name string, qtype dns.Type) ([]byte, error) {
	svcbQuery := &dns.Msg {
		MsgHdr: dns.MsgHdr{
			Id: dns.Id(),
			Response: true,
			Opcode: dns.OpcodeQuery,
			Authoritative: false,
			Truncated: false,
			RecursionDesired: true,
			RecursionAvailable: false,
			Rcode: 0,
		},
		Question: make([]dns.Question, 1),
		Answer: make([]dns.RR, 1),
	}
	svcbQuery.Question[0] = dns.Question{
		Name:   dns.Fqdn(name),
		Qtype:  uint16(qtype),
		Qclass: uint16(dns.ClassINET),
	}

	kvpairs := make(map[string]string)
	kvpairs["alpn"] = "h2"
	kvpairs["dohuri"] = "https://odoh-target-dot-odoh-254517.appspot.com/dns-query"
	//svcbQuery.Answer[0] = &dns.SVCB{
	//	Hdr: dns.RR_Header{Name: svcbQuery.Question[0].Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 0},
	//	SvcFieldPriority: 0,
	//	SvcDomainName: dns.Fqdn(name),
	//	SvcFieldValue: kvpairs,
	//}

	packedSVCBMessage, err := svcbQuery.Pack()
	if err != nil {
		return nil, err
	}

	return packedSVCBMessage, nil
}

func backup_main() {
	vendPtr := flag.Bool("vend", false, "Vend a SVCB record")
	namePtr := flag.String("qname", "apple.com", "Query name")
	typePtr := flag.String("qtype", "AAAA", "Query type (A, AAAA)")
	serverPtr := flag.String("doh-uri", "http://localhost:8080/dns-query", "DoH server URI template")
	flag.Parse()

	// Id                 uint16
	// Response           bool
	// Opcode             int
	// Authoritative      bool
	// Truncated          bool
	// RecursionDesired   bool
	// RecursionAvailable bool
	// Zero               bool
	// AuthenticatedData  bool
	// CheckingDisabled   bool
	// Rcode              int

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode: dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}

	qtype := dns.Type(dns.TypeAAAA)
	if *typePtr == "A" {
		qtype = dns.Type(dns.TypeA)
	}
	qname := *namePtr

	if *vendPtr {
		packedRecord, err := vendRecord(qname, qtype)
		if err != nil  {
			log.Fatal(err)
			return
		}

		fmt.Printf("%x", packedRecord)
	} else {
		m.Question[0] = dns.Question{
			Name: dns.Fqdn(qname), 
			Qtype: uint16(qtype),
			Qclass: uint16(dns.ClassINET),
		}
		m.Id = 0 // clients SHOULD set this to 0

		packed, err := m.Pack()
		if err != nil {
			log.Fatal(err)
			return
		}

		msg := &dns.Msg{}
		if err := msg.Unpack(packed); err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s", packed)

		req, err := http.NewRequest("POST", *serverPtr, bytes.NewReader(packed))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/dns-message")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()
	}
}
