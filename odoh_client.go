package main

import (
	"flag"
	"log"
	"fmt"
	"bytes"
	"net/http"
	"github.com/miekg/dns"
)

func main() {
	namePtr := flag.String("qname", "apple.com", "Query name")
	typePtr := flag.String("qtype", "AAAA", "Query type (A, AAAA)")
	serverPtr := flag.String("doh-uri", "http://localhost:8080/dns-query", "DoH server URI template")
	flag.Parse()

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:            dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}

	qtype := dns.TypeAAAA
	if *typePtr == "A" {
		qtype = dns.TypeA
	}

	m.Question[0] = dns.Question{Name: dns.Fqdn(*namePtr), Qtype: qtype, Qclass: uint16(dns.ClassINET)}
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