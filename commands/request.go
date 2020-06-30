package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/bifurcation/hpke"
	"github.com/chris-wood/dns"
	"github.com/chris-wood/odoh"
	"github.com/kelindar/binary"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	OBLIVIOUS_DOH = "application/oblivious-dns-message"
)

func createPlainQueryResponse(serializedDnsQueryString []byte) (response *dns.Msg, err error) {
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

func createOdohQueryResponse(serializedOdohDnsQueryString []byte) (response *odoh.ObliviousDNSMessage, err error) {
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

	responseHeader := resp.Header.Get("Content-Type")
	if responseHeader != OBLIVIOUS_DOH {
		log.Fatalf("[WARN] The returned response does not have the %v Content-Type\n", OBLIVIOUS_DOH)
		// TODO: Design decision, break here.
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	hexBodyBytes := hex.EncodeToString(bodyBytes)
	log.Printf("[ODOH] Hex Encrypted Response : %v\n", hexBodyBytes)

	odohQueryResponse, err := odoh.UnmarshalDNSMessage(bodyBytes)

	if err != nil {
		log.Fatalln("Unable to Unmarshal the Encrypted ODOH Response")
	}

	return odohQueryResponse, nil
}

func retrievePublicKey(ip string) (response odoh.ObliviousDNSPublicKey, err error) {
	req, err := http.NewRequest(http.MethodGet, "https://" + ip + "/pk", nil)
	if err != nil {
		log.Fatalln(err)
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var odohPublicKey odoh.ObliviousDNSPublicKey
	err = binary.Unmarshal(bodyBytes, &odohPublicKey)

	return odohPublicKey, err
}


func plainDnsRequest(c *cli.Context) error {
	domainName := c.String("domain")
	dnsTypeString := c.String("dnstype")

	dnsType := dnsQueryStringToType(dnsTypeString)

	fmt.Println("[DNS] Request : ", domainName, dnsTypeString)

	serializedDnsQuestion := prepareDnsQuestion(domainName, dnsType)
	response, err := createPlainQueryResponse(serializedDnsQuestion)

	if err != nil {
		log.Fatalf("Unable to obtain a valid response for the DNS Query. %v\n", err)
	}

	fmt.Println("[DNS] Response : \n", response)
	return nil
}

func obliviousDnsRequest(c *cli.Context) error {
	domainName := c.String("domain")
	dnsTypeString := c.String("dnstype")
	key := c.String("key")
	targetIP := c.String("target")

	odohPublicKeyBytes, err := retrievePublicKey(targetIP)

	if err != nil {
		fmt.Println("Failed to obtain the public key of the target resolver.", err)
		return nil
	}

	dnsType := dnsQueryStringToType(dnsTypeString)

	fmt.Println("[ODNS] Request : ", domainName, dnsTypeString, key)

	serializedODoHQueryMessage, err := prepareOdohQuestion(domainName, dnsType, []byte(key), odohPublicKeyBytes)

	if err != nil {
		log.Fatalln("Unable to Create the ODoH Query with the DNS Question")
	}

	odohMessage, err := createOdohQueryResponse(serializedODoHQueryMessage)
	if err != nil {
		log.Fatalln("Unable to Obtain an Encrypted Response from the Target Resolver")
	}

	dnsResponse, err := ValidateEncryptedResponse(odohMessage, []byte(key))
	fmt.Println("[ODOH] Response : \n", dnsResponse)
	return nil
}

func ValidateEncryptedResponse(message *odoh.ObliviousDNSMessage, key []byte) (response *dns.Msg, err error) {
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
		log.Fatalln("Unable to decrypt the obtained response using the symmetric key sent.")
	}

	log.Printf("[ODOH] [Decrypted Response] : %v\n", decryptedResponse)

	dnsBytes, err := parseDnsResponse(decryptedResponse)
	if err != nil {
		log.Fatalln("Unable to parse DNS bytes after decryption of the message from target server.")
		return nil, err
	}

	return dnsBytes, err
}

func getTargetPublicKey(c *cli.Context) error {
	targetIP := c.String("ip")
	/*
	Ideally, this procedure will be replaced by a DNSSEC validation step followed by the retrieval of the PublicKey
	from the SVCB or HTTPSSVC records of the target resolver by the client. For now, we bypass this procedure and
	implement a procedure to retrieve the ObliviousDNSPublicKey which is used for encryption.
	 */
	fmt.Printf("Retrieving the Public Key from [%v]\n", targetIP)

	odohPublicKeyBytes, _ := retrievePublicKey(targetIP)
	fmt.Printf("[PK] Expectation : %v", odohPublicKeyBytes)
	return nil
}
