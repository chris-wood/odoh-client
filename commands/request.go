package commands

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/chris-wood/dns"
	"github.com/chris-wood/odoh"
	"github.com/cisco/go-hpke"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

const (
	OBLIVIOUS_DOH = "application/oblivious-dns-message"
	TARGET_HTTP_MODE = "https"
	PROXY_HTTP_MODE = "https"
)

func createPlainQueryResponse(hostname string, serializedDnsQueryString []byte) (response *dns.Msg, err error) {
	client := http.Client{}
	queryUrl := fmt.Sprintf("https://%s/dns-query", hostname)
	req, err := http.NewRequest(http.MethodGet, queryUrl, nil)
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

func prepareHttpRequest(serializedBody []byte, useProxy bool, targetIP string, proxy string) (req *http.Request, err error) {
	var baseurl string
	var queries url.Values

	if useProxy != true {
		fmt.Printf("Preparing the query to dns-query endpoint with %v data\n.", serializedBody)
		baseurl = fmt.Sprintf("%s://%s/%s", TARGET_HTTP_MODE, targetIP, "dns-query")
		req, err = http.NewRequest(http.MethodPost, baseurl,  bytes.NewBuffer(serializedBody))
		queries = req.URL.Query()
	} else {
		baseurl = fmt.Sprintf("%s://%s/%s", PROXY_HTTP_MODE, proxy, "proxy")
		req, err = http.NewRequest(http.MethodPost, baseurl,  bytes.NewBuffer(serializedBody))
		queries = req.URL.Query()
		queries.Add("targethost", targetIP)
		queries.Add("targetpath", "/dns-query")
	}

	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	req.URL.RawQuery = queries.Encode()

	return req, err
}

func createOdohQueryResponse(serializedOdohDnsQueryString []byte, useProxy bool, targetIP string, proxy string, client *http.Client) (response *odoh.ObliviousDNSMessage, err error) {
	req, err := prepareHttpRequest(serializedOdohDnsQueryString, useProxy, targetIP, proxy)

	if err != nil {
		log.Fatalln(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	responseHeader := resp.Header.Get("Content-Type")
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to read response body.")
		log.Fatalln(err)
	}
	if responseHeader != OBLIVIOUS_DOH {
		log.Printf("[WARN] The returned response does not have the %v Content-Type from %v with response %v\n", OBLIVIOUS_DOH, targetIP, string(bodyBytes))
		return &odoh.ObliviousDNSMessage{
			MessageType:      odoh.ResponseType,
			KeyID:            []byte{},
			EncryptedMessage: []byte{},
		}, errors.New(fmt.Sprintf("Did not obtain the correct headers from %v with response %v", targetIP, string(bodyBytes)))
	}

	hexBodyBytes := hex.EncodeToString(bodyBytes)
	log.Printf("[ODOH] Hex Encrypted Response : %v\n", hexBodyBytes)

	odohQueryResponse, err := odoh.UnmarshalDNSMessage(bodyBytes)

	if err != nil {
		log.Printf("Unable to Unmarshal the Encrypted ODOH Response")
		return nil, err
	}

	return odohQueryResponse, nil
}

func DiscoverProxiesAndTargets(hostname string, client *http.Client) (response DiscoveryServiceResponse, err error) {
	req, err := http.NewRequest(http.MethodGet, TARGET_HTTP_MODE + "://" + hostname, nil)
	if err != nil {
		log.Fatalf("Unable to discover the proxies and targets")
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Unable to obtain a response from the discovery service")
	}
	defer resp.Body.Close()

	var data DiscoveryServiceResponse
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&data)
	if err != nil {
		log.Fatalf("Unable to decode the obtained JSON response from the Discovery service %v\n", err)
	}
	return data, nil
}

func RetrievePublicKey(ip string, clientProvided *http.Client) (response odoh.ObliviousDNSPublicKey, err error) {
	req, err := http.NewRequest(http.MethodGet, TARGET_HTTP_MODE + "://" + ip + "/pk", nil)
	if err != nil {
		log.Fatalln(err)
	}

	client := clientProvided
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	odohPublicKey := odoh.UnMarshalObliviousDNSPublicKey(bodyBytes)

	return odohPublicKey, err
}


func plainDnsRequest(c *cli.Context) error {
	domainName := c.String("domain")
	dnsTypeString := c.String("dnstype")
	dnsTargetServer := c.String("target")

	dnsType := dnsQueryStringToType(dnsTypeString)

	fmt.Println("[DNS] Request : ", domainName, dnsTypeString)

	serializedDnsQuestion := prepareDnsQuestion(domainName, dnsType)
	response, err := createPlainQueryResponse(dnsTargetServer, serializedDnsQuestion)

	if err != nil {
		log.Fatalf("Unable to obtain a valid response for the DNS Query. %v\n", err)
	}

	fmt.Println("[DNS] Response : \n", response)
	return nil
}

func obliviousDnsRequest(c *cli.Context) error {
	domainName := c.String("domain")
	dnsTypeString := c.String("dnstype")
	targetIP := c.String("target")
	proxy := c.String("proxy")

	var useproxy bool;
	if len(proxy) > 0 {
		fmt.Println("Using proxy since proxy is specified.")
		useproxy = true
	}

	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Unable to read random bytes to make a symmetric key.\n")
	}

	if useproxy == true {
		fmt.Printf("Using %v as the proxy to send the ODOH Message\n", proxy)
	}
	client := http.Client{}

	odohPublicKeyBytes, err := RetrievePublicKey(targetIP, &client)

	if err != nil {
		fmt.Println("Failed to obtain the public key of the target resolver.", err)
		return nil
	}

	fmt.Printf("PK Correctly fetched : %v\n", odohPublicKeyBytes)

	dnsType := dnsQueryStringToType(dnsTypeString)

	fmt.Println("[ODNS] Request : ", domainName, dnsTypeString, key)

	serializedODoHQueryMessage, err := prepareOdohQuestion(domainName, dnsType, key, odohPublicKeyBytes)

	if err != nil {
		log.Fatalln("Unable to Create the ODoH Query with the DNS Question")
	}

	odohMessage, err := createOdohQueryResponse(serializedODoHQueryMessage, useproxy, targetIP, proxy, &client)
	if err != nil {
		log.Fatalln("Unable to Obtain an Encrypted Response from the Target Resolver")
	}

	dnsResponse, err := validateEncryptedResponse(odohMessage, key)
	fmt.Println("[ODOH] Response : \n", dnsResponse)
	return nil
}

func validateEncryptedResponse(message *odoh.ObliviousDNSMessage, key []byte) (response *dns.Msg, err error) {
	odohResponse := odoh.ObliviousDNSResponse{ResponseKey: key}

	responseMessageType := message.MessageType
	if responseMessageType != odoh.ResponseType {
		log.Fatalln("[ERROR] The data obtained from the server is not of the response type")
	}

	encryptedResponse := message.EncryptedMessage

	kemID := hpke.DHKEM_X25519
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AESGCM128

	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)

	if err != nil {
		log.Fatalln("Unable to initialize HPKE Cipher Suite", err)
	}

	// The following lines are hardcoded on the server side for `aad`
	responseKeyId := []byte{0x00, 0x00}
	aad := append([]byte{0x02}, responseKeyId...) // message_type = 0x02, with an empty keyID

	decryptedResponse, err := odohResponse.DecryptResponse(suite, aad, encryptedResponse)

	if err != nil {
		log.Printf("Unable to decrypt the obtained response using the symmetric key sent.")
	}

	log.Printf("[ODOH] [Decrypted Response] : %v\n", decryptedResponse)

	dnsBytes, err := parseDnsResponse(decryptedResponse)
	if err != nil {
		log.Printf("Unable to parse DNS bytes after decryption of the message from target server.")
		return nil, err
	}

	return dnsBytes, err
}

func getTargetPublicKey(c *cli.Context) error {
	client := http.Client{}
	targetIP := c.String("ip")
	/*
	Ideally, this procedure will be replaced by a DNSSEC validation step followed by the retrieval of the PublicKey
	from the SVCB or HTTPSSVC records of the target resolver by the client. For now, we bypass this procedure and
	implement a procedure to retrieve the ObliviousDNSPublicKey which is used for encryption.
	 */
	fmt.Printf("Retrieving the Public Key from [%v]\n", targetIP)

	odohPublicKeyBytes, _ := RetrievePublicKey(targetIP, &client)
	fmt.Printf("[PK] Expectation : %v", odohPublicKeyBytes)
	return nil
}
