package commands

import (
	"fmt"
	"errors"
	"github.com/chris-wood/odoh"
	"github.com/urfave/cli"
	"github.com/miekg/dns"
	"io/ioutil"
	"net/http"
)

func fetchTargetConfigsFromWellKnown(targetName string) (odoh.ObliviousDoHConfigs, error) {
	req, err := http.NewRequest(http.MethodGet, TARGET_HTTP_MODE + "://" + targetName + ODOH_CONFIG_WELLKNOWN_URL, nil)
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}

	return odoh.UnmarshalObliviousDoHConfigs(bodyBytes)
}

func fetchTargetConfigsFromDNS(targetName string) (odoh.ObliviousDoHConfigs, error) {
	dnsQuery := new(dns.Msg)
	dnsQuery.SetQuestion(targetName, dns.TypeHTTPS)
	dnsQuery.RecursionDesired = true
	packedDnsQuery, err := dnsQuery.Pack()
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}

	response, err := createPlainQueryResponse(DEFAULT_DOH_SERVER, packedDnsQuery)
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}

	if response.Rcode != dns.RcodeSuccess {
		return odoh.ObliviousDoHConfigs{}, errors.New(fmt.Sprintf("DNS response failure: %v", response.Rcode))
	}

	for _, answer := range(response.Answer) {
		httpsResponse, ok := answer.(*dns.HTTPS)
		if ok {
			for _, value := range(httpsResponse.Value) {
				fmt.Println(value.Key(), value.String())
				// TODO(caw): parse the value and call odoh.UnmarshalObliviousDoHConfigs(...)
			}
		}
	}

	return odoh.ObliviousDoHConfigs{}, nil
}

func fetchTargetConfigs(targetName string) (odoh.ObliviousDoHConfigs, error) {
	odohConfigs, err := fetchTargetConfigsFromDNS(targetName)
	if err == nil {
		return odohConfigs, err
	}

	// Fall back to the well-known endpoint if we can't read from DNS
	return fetchTargetConfigsFromWellKnown(targetName)
}

func getTargetConfigs(c *cli.Context) error {
	targetName := c.String("target")

	odohConfigs, err := fetchTargetConfigs(targetName)
	if err != nil {
		return err
	}

	fmt.Printf("%x", odohConfigs.Marshal())
	return nil
}
