package commands

import (
	"crypto/rand"
	"fmt"
	"github.com/chris-wood/dns"
	"github.com/chris-wood/odoh"
	"github.com/cisco/go-hpke"
	"github.com/urfave/cli"
	"log"
	"net/http"
	"time"
)

func getKemIDDescriptionById(kemID hpke.KEMID) string {
	var kemDescription string
	switch kemID {
	case hpke.DHKEM_X25519:
		kemDescription = "DHKEM_X22519"
		break
	case hpke.DHKEM_X448:
		kemDescription = "DHKEM_X448"
		break
	case hpke.DHKEM_P256:
		kemDescription = "DHKEM_P256"
		break
	case hpke.DHKEM_P521:
		kemDescription = "DHKEM_P521"
		break
	}
	return kemDescription
}

func getKdfIDDescriptionById(kdfID hpke.KDFID) string {
	var kdfDescription string
	switch kdfID {
	case hpke.KDF_HKDF_SHA256:
		kdfDescription = "KDF_HKDF_SHA256"
		break
	case hpke.KDF_HKDF_SHA384:
		kdfDescription = "KDF_HKDF_SHA384"
		break
	case hpke.KDF_HKDF_SHA512:
		kdfDescription = "KDF_HKDF_SHA512"
		break
	}
	return kdfDescription
}

func getAeadIDDescriptionByID(aeadID hpke.AEADID) string {
	var aeadDescription string
	switch aeadID {
	case hpke.AEAD_AESGCM128:
		aeadDescription = "AEAD_AESGCM128"
		break
	case hpke.AEAD_AESGCM256:
		aeadDescription = "AEAD_AESGCM256"
		break
	case hpke.AEAD_CHACHA20POLY1305:
		aeadDescription = "AEAD_CHACHA20POLY1305"
		break
	}
	return aeadDescription
}

func MicroBenchmarkODOHKeyGeneration(kemID hpke.KEMID, kdfID hpke.KDFID, aeadID hpke.AEADID, total int, repeat int) {
	kemDescription := getKemIDDescriptionById(kemID)
	kdfDescription := getKdfIDDescriptionById(kdfID)
	aeadDescription := getAeadIDDescriptionByID(aeadID)

	var keyPairsUsed int = total

	for benchCount := 0; benchCount < repeat; benchCount++ {
		keypairs := make([]odoh.ObliviousDNSKeyPair, keyPairsUsed)
		publicKeys := make([]odoh.ObliviousDNSPublicKey, keyPairsUsed)
		start := time.Now().UnixNano()
		for index := 0; index < keyPairsUsed; index++ {
			kp, err := odoh.CreateKeyPair(kemID, kdfID, aeadID)
			if err != nil {
				log.Printf("Unable to create a keypair.")
			}
			keypairs[index] = kp
			publicKeys[index] = kp.PublicKey
		}
		end := time.Now().UnixNano()
		timePerKeyGeneration := (end - start) / (1000.0 * 1000.0)
		log.Printf("%v,%v,%v,%v,%v\n", kemDescription, kdfDescription, aeadDescription, keyPairsUsed, timePerKeyGeneration)
	}
}

func MicroBenchmarkODOHEncryption(kemID hpke.KEMID, kdfID hpke.KDFID, aeadID hpke.AEADID, total int, repeat int) {
	kemDescription := getKemIDDescriptionById(kemID)
	kdfDescription := getKdfIDDescriptionById(kdfID)
	aeadDescription := getAeadIDDescriptionByID(aeadID)

	kp, err := odoh.CreateKeyPair(kemID, kdfID, aeadID)
	if err != nil {
		log.Printf("Unable to create a key pair.")
	}

	filepath := "dataset-full.csv"
	filterCount := uint64(total)

	allDomains, err := readLines(filepath)

	if err != nil {
		log.Printf("Failed to read the file correctly. %v", err)
	}

	hostnames := shuffleAndSlice(allDomains, filterCount)
	symmetricKeys := prepareSymmetricKeys(total)

	queriesToEncrypt := make([]odoh.ObliviousDNSQuery, filterCount)
	prepareQuestionStart := time.Now().UnixNano()
	for index, hostname := range hostnames {
		dnsMessage := prepareDnsQuestion(hostname, dns.TypeA)
		odohQuery := odoh.ObliviousDNSQuery{
			ResponseKey: symmetricKeys[index],
			DnsMessage:  dnsMessage,
		}
		queriesToEncrypt[index] = odohQuery
	}
	prepareQuestionEnd := time.Now().UnixNano()
	timeToPrepareEachQuestion := (prepareQuestionEnd - prepareQuestionStart) / (1000.0 * 1000.0)

	for benchCount := 0; benchCount < repeat; benchCount++ {
		encryptedQueries := make([]odoh.ObliviousDNSMessage, len(queriesToEncrypt))
		start := time.Now().UnixNano()
		for index, query := range queriesToEncrypt {
			encryptedQuery, err := kp.PublicKey.EncryptQuery(query)
			if err != nil {
				log.Printf("Failed to encrypt the query using the public key")
			}
			encryptedQueries[index] = encryptedQuery
		}
		end := time.Now().UnixNano()
		timeForEachEncryption := (end - start) / (1000.0 * 1000.0)

		TotalQueriesByteSizes := 0
		for _, query := range queriesToEncrypt {
			size := len(query.Marshal())
			TotalQueriesByteSizes += size
		}
		averageQueryByteSize := float64(TotalQueriesByteSizes) / float64(len(queriesToEncrypt))

		TotalEncryptedQueriesByteSizes := 0
		for _, encQuery := range encryptedQueries {
			size := len(encQuery.Marshal())
			TotalEncryptedQueriesByteSizes += size
		}
		averageEncryptedQueryByteSize := float64(TotalEncryptedQueriesByteSizes) / float64(len(encryptedQueries))

		log.Printf("%v,%v,%v,%v,%v,%v,%v,%v", kemDescription, kdfDescription, aeadDescription, total,
			timeForEachEncryption, averageQueryByteSize, averageEncryptedQueryByteSize, timeToPrepareEachQuestion)
	}
}

func prepareSymmetricKeysForAEAD(quantity int, aeadID hpke.AEADID) [][]byte {
	// Assume that all the keys necessary for the experiment are 16 bytes.
	var keySize int
	switch aeadID {
	case hpke.AEAD_AESGCM128:
		keySize = 16
		break
	case hpke.AEAD_AESGCM256:
		keySize = 32
		break
	case hpke.AEAD_CHACHA20POLY1305:
		keySize = 32
		break
	}
	result := make([][]byte, quantity)
	for i := 0; i < quantity; i++ {
		key := make([]byte, keySize)
		_, err := rand.Read(key)
		if err != nil {
			log.Fatalf("Unable to read random bytes to make a symmetric Key.\n")
		}
		result[i] = key
	}
	return result
}

func MicroBenchmarkEncryptionDecryptionSizes(kemID hpke.KEMID, kdfID hpke.KDFID, aeadID hpke.AEADID, total int, repeat int, hostnames []string) {
	kemDescription := getKemIDDescriptionById(kemID)
	kdfDescription := getKdfIDDescriptionById(kdfID)
	aeadDescription := getAeadIDDescriptionByID(aeadID)

	QUERY_KEY := fmt.Sprintf("%v/%v/%v", kemDescription, kdfDescription, aeadDescription)

	kp, err := odoh.CreateKeyPair(kemID, kdfID, aeadID)
	if err != nil {
		log.Printf("Unable to create a key pair.")
	}

	symmetricKeys := prepareSymmetricKeysForAEAD(total, aeadID)

	queriesToEncrypt := make([]odoh.ObliviousDNSQuery, total)
	TotalDNSMessageByteSize := 0
	for index, hostname := range hostnames {
		dnsMessage := prepareDnsQuestion(hostname, dns.TypeA)
		odohQuery := odoh.ObliviousDNSQuery{
			ResponseKey: symmetricKeys[index],
			DnsMessage:  dnsMessage,
		}
		TotalDNSMessageByteSize += len(dnsMessage)
		queriesToEncrypt[index] = odohQuery
	}

	client := &http.Client{Transport: &http.Transport{TLSHandshakeTimeout: 0 * time.Second, MaxIdleConnsPerHost: 1024}}

	for benchCount := 0; benchCount < repeat; benchCount++ {
		encryptedQueries := make([]odoh.ObliviousDNSMessage, len(queriesToEncrypt))
		encryptionStart := time.Now().UnixNano()
		for index, query := range queriesToEncrypt {
			eachEncryptionStart := time.Now()
			encryptedQuery, err := kp.PublicKey.EncryptQuery(query)
			if err != nil {
				log.Printf("Failed to encrypt the query using the public key")
			}
			eachEncryptionEnd := time.Since(eachEncryptionStart)
			encryptedQueries[index] = encryptedQuery
			log.Printf("%v,%v,%v", QUERY_KEY, "Encryption", eachEncryptionEnd.Nanoseconds())
		}
		encryptionEnd := time.Now().UnixNano()
		timePerEncryption := float64(encryptionEnd-encryptionStart) / float64(1000.0*1000.0)

		decryptionStart := time.Now().UnixNano()
		for _, encQuery := range encryptedQueries {
			eachDecryptionStart := time.Now()
			_, err := kp.DecryptQuery(encQuery)
			if err != nil {
				log.Printf("Unable to decrypt message")
			}
			eachDecryptionEnd := time.Since(eachDecryptionStart)
			log.Printf("%v,%v,%v", QUERY_KEY, "Decryption", eachDecryptionEnd.Nanoseconds())
		}
		decryptionEnd := time.Now().UnixNano()
		timePerDecryption := (decryptionEnd - decryptionStart) / (1000.0 * 1000.0)

		log.Printf("ENC/DEC %v,%v,%v", QUERY_KEY, timePerEncryption, timePerDecryption)

		TotalQueriesByteSizes := 0
		for _, query := range queriesToEncrypt {
			size := len(query.Marshal())
			TotalQueriesByteSizes += size
		}

		TotalEncryptedQueriesByteSizes := 0
		for _, encQuery := range encryptedQueries {
			size := len(encQuery.Marshal())
			TotalEncryptedQueriesByteSizes += size
		}

		TotalDNSAnswerByteSizes := 0
		TotalEncryptedDNSAnswerByteSizes := 0

		for _, encQuery := range encryptedQueries {
			dnsQuery, err := kp.DecryptQuery(encQuery)
			if err != nil {
				log.Printf("Unable to decrypt the message")
			}
			response, err := createPlainQueryResponse("cloudflare-dns.com", dnsQuery.DnsMessage, "", client)
			log.Printf("%v", response)
			suite, err := kp.CipherSuite()
			responseKeyId := []byte{0x00, 0x00}
			aad := append([]byte{byte(odoh.ResponseType)}, responseKeyId...) // message_type = 0x02, with an empty keyID
			responseBytes, err := response.Pack()
			encryptedResponse, err := dnsQuery.EncryptResponse(suite, aad, responseBytes)
			TotalDNSAnswerByteSizes += len(responseBytes)
			TotalEncryptedDNSAnswerByteSizes += len(encryptedResponse)
		}

		// [Count, DNS Query Size, ODOH Query Size, Encrypted ODOH Query Size, Encrypted Response Size, DNS Answer Size]
		log.Printf("%v,%v,%v,%v,%v,%v,%v",
			QUERY_KEY, total, TotalDNSMessageByteSize, TotalQueriesByteSizes, TotalEncryptedQueriesByteSizes, TotalEncryptedDNSAnswerByteSizes, TotalDNSAnswerByteSizes)
	}
}

func microBenchmarkHandler(c *cli.Context) {
	total := c.Int("total")
	repeat := c.Int("repeat")

	//availableKEMs := []hpke.KEMID{hpke.DHKEM_X25519, hpke.DHKEM_X448, hpke.DHKEM_P256, hpke.DHKEM_P521}
	availableKEMs := []hpke.KEMID{hpke.DHKEM_X25519}
	availableKDFs := []hpke.KDFID{hpke.KDF_HKDF_SHA256, hpke.KDF_HKDF_SHA384, hpke.KDF_HKDF_SHA512}
	availableAEADs := []hpke.AEADID{hpke.AEAD_AESGCM128, hpke.AEAD_AESGCM256, hpke.AEAD_CHACHA20POLY1305}

	filepath := "dataset-full.csv"
	filterCount := uint64(total)

	allDomains, err := readLines(filepath)

	if err != nil {
		log.Printf("Failed to read the file correctly. %v", err)
	}

	hostnames := shuffleAndSlice(allDomains, filterCount)

	for _, kemID := range availableKEMs {
		for _, kdfID := range availableKDFs {
			for _, aeadID := range availableAEADs {
				MicroBenchmarkDNSQuerySize(total)
				MicroBenchmarkODOHKeyGeneration(kemID, kdfID, aeadID, total, repeat)
				MicroBenchmarkODOHEncryption(kemID, kdfID, aeadID, total, repeat)
				MicroBenchmarkEncryptionDecryptionSizes(kemID, kdfID, aeadID, total, repeat, hostnames)
			}
		}
	}
}

func MicroBenchmarkDNSQuerySize(total int) {
	filepath := "dataset-full.csv"
	filterCount := uint64(total)

	allDomains, err := readLines(filepath)

	if err != nil {
		log.Printf("Failed to read the file correctly. %v", err)
	}

	hostnames := shuffleAndSlice(allDomains, filterCount)

	for benchCount := 0; benchCount < 10; benchCount++ {
		TotalDNSMessageByteSize := 0
		for _, hostname := range hostnames {
			dnsMessage := prepareDnsQuestion(hostname, dns.TypeA)
			TotalDNSMessageByteSize += len(dnsMessage)
		}
		log.Printf("[Round %v] TOTAL SIZE OF DNS MESSAGE BYTES : %v", benchCount+1, TotalDNSMessageByteSize)
	}

}
