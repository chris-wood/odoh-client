package commands

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/chris-wood/dns"
	"github.com/chris-wood/odoh"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"net/http"
)

func createPlainQueryRequest(serializedDnsQueryString []byte) (response *dns.Msg, err error) {
	client := http.Client{}
	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/dns-query", nil)
	if err != nil {
		log.Fatalln(err)
	}

	queries := req.URL.Query()
	encodedString := base64.RawURLEncoding.EncodeToString(serializedDnsQueryString)
	queries.Add("dns", encodedString)
	req.Header.Set("Content-Type", "application/dns-message")
	req.URL.RawQuery = queries.Encode()

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	dnsBytes, err := parseDnsResponse(bodyBytes)

	return dnsBytes, nil
}

func createOdohQueryRequest(serializedOdohDnsQueryString []byte) (response *odoh.ObliviousDNSMessage, err error) {
	client := http.Client{}
	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/dns-query",
		bytes.NewBuffer(serializedOdohDnsQueryString))
	if err != nil {
		log.Fatalln(err)
	}

	queries := req.URL.Query()
	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	req.URL.RawQuery = queries.Encode()

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("ODNS Bytes : %v\n", bodyBytes)
	return &odoh.ObliviousDNSMessage{}, nil
}


func plainDnsRequest(c *cli.Context) error {
	domainName := c.String("domain")
	dnsTypeString := c.String("dnstype")

	dnsType := dnsQueryStringToType(dnsTypeString)

	fmt.Println("[DNS] Request : ", domainName, dnsTypeString)

	serializedDnsQuestion := prepareDnsQuestion(domainName, dnsType)
	response, _ := createPlainQueryRequest(serializedDnsQuestion)
	fmt.Println("[DNS] Response : \n", response)
	return nil
}

func obliviousDnsRequest(c *cli.Context) error {
	domainName := c.String("domain")
	dnsTypeString := c.String("dnstype")
	key := c.String("key")

	dnsType := dnsQueryStringToType(dnsTypeString)

	fmt.Println("[ODNS] Request : ", domainName, dnsTypeString, key)

	serializedODnsQuestion := prepareOdohQuestion(domainName, dnsType, []byte(key))
	response, _ := createOdohQueryRequest(serializedODnsQuestion)
	fmt.Println("[ODNS] Response : \n", response)
	return nil
}
