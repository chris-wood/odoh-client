package commands

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"github.com/chris-wood/dns"
	"github.com/chris-wood/odoh"
	"github.com/urfave/cli"
	"log"
	mathrand "math/rand"
	"net/http"
	"os"
	"time"
)

type Experiment struct {
	Hostname        string
	DnsType         uint16
	Key             []byte
	TargetPublicKey odoh.ObliviousDNSPublicKey
	Target          string
	// Timing parameters
	STime    time.Time
	ETime    time.Time
	Response []byte
}

func (e *Experiment) serialize() string {
	exp := &e
	response, err := json.Marshal(exp)
	if err != nil {
		log.Printf("Unable to log the information correctly.")
	}
	return string(response)
}

func prepareSymmetricKeys(quantity int) [][]byte {
	// Assume that all the keys necessary for the experiment are 16 bytes.
	result := make([][]byte, quantity)
	start := time.Now()
	for i := 0; i < quantity; i++ {
		key := make([]byte, 16)
		_, err := rand.Read(key)
		if err != nil {
			log.Fatalf("Unable to read random bytes to make a symmetric Key.\n")
		}
		result[i] = key
	}
	log.Printf("Time (ms) to generate %v symmetric keys : [%v]", len(result), time.Since(start).Microseconds())
	return result
}

func workflow(e Experiment, client *http.Client, channel chan Experiment) {
	hostname := e.Hostname
	dnsType := e.DnsType
	symmetricKey := e.Key
	targetPublicKey := e.TargetPublicKey
	target := e.Target

	start := time.Now()
	requestId := sha256.Sum256(symmetricKey)
	hashingTime := time.Since(start)
	serializedODoHQueryMessage, err := PrepareOdohQuestion(hostname, dnsType, symmetricKey, targetPublicKey)
	timeToPrepareQuestionAndSerialize := time.Since(start)
	if err != nil {
		log.Fatalf("Error while preparing OdohQuestion: %v", err)
	}
	requestTime := time.Since(start)
	odohMessage, err := CreateOdohQueryResponse(serializedODoHQueryMessage, false, target, "", client)
	responseTime := time.Since(start)

	if err != nil {
		exp := Experiment{
			Hostname:        hostname,
			DnsType:         dnsType,
			Key:             symmetricKey,
			TargetPublicKey: targetPublicKey,
			Target:          target,
			STime:           e.STime,
			ETime:           time.Now(),
			Response:        []byte(err.Error()),
		}
		channel <- exp
		return
	}

	dnsAnswer, err := ValidateEncryptedResponse(odohMessage, symmetricKey)
	validationTime := time.Since(start)

	dnsAnswerBytes, err := dnsAnswer.Pack()

	log.Printf("=======ODOH Request for [%v]========\n", hostname)
	log.Printf("Request ID : [%x]\n", requestId[:])
	log.Printf("Start Time : [%v]\n", start.UnixNano())
	log.Printf("Time @ Hash the Symmetric Key as ID: [%v]\n", hashingTime.Microseconds())
	log.Printf("Time @ Prepare Question and Serialize : [%v]\n", timeToPrepareQuestionAndSerialize.Microseconds())
	log.Printf("Time @ Starting ODOH Request  : [%v]\n", requestTime.Microseconds())
	log.Printf("The network requests come in between here.\n")
	log.Printf("Time @ Received ODOH Response : [%v]\n", responseTime.Microseconds())
	log.Printf("Time @ Finished Validation Response : [%v]\n", validationTime.Microseconds())
	log.Printf("DNS Answer : [%v]\n", dnsAnswerBytes)
	log.Printf("====================================")
	exp := Experiment{
		Hostname:        hostname,
		DnsType:         dnsType,
		Key:             symmetricKey,
		TargetPublicKey: targetPublicKey,
		Target:          target,
		STime:           e.STime,
		ETime:           time.Now(),
		Response:        dnsAnswerBytes,
	}
	log.Printf("Experiment : %v", exp.serialize())
	channel <- exp
}

func responseHandler(numberOfChannels int, responseChannel chan Experiment) []string {
	responses := make([]string, 0)
	for index := 0; index < numberOfChannels; index++ {
		answerStructure := <- responseChannel
		answer := answerStructure.Response
		sTime := answerStructure.STime
		eTime := answerStructure.ETime
		hostname := answerStructure.Hostname
		target := answerStructure.Target
		log.Printf("Response %v\n", index)
		log.Printf("Size of the Response for [%v] is [%v] and [%v] to [%v] = [%v] using Target [%v]", hostname, len(answer), sTime.UnixNano(), eTime.UnixNano(), eTime.Sub(sTime).Microseconds(), target)
		responses = append(responses, answerStructure.serialize())
	}
	return responses
}

func benchmarkClient(c *cli.Context) {
	f, err := os.OpenFile("data/data-test.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Unable to create a log file to log data into.")
	}
	defer f.Close()
	log.SetOutput(f)

	// The Preparation Phase of the request.
	filepath := c.String("data")
	filterCount := c.Uint64("pick")
	all_domains, err := readLines(filepath)

	if err != nil {
		log.Printf("Failed to read the file correctly. %v", err)
	}

	hostnames := shuffleAndSlice(all_domains, filterCount)
	log.Printf("Now operating on a total size of : [%v] hostnames", len(hostnames))

	// Create a base state of the experiment
	state := GetInstance()
	telemetryState := getTelemetryInstance()
	telemetryResponse := telemetryState.getClusterInformation()
	log.Printf("Server: %s", telemetryResponse["version"].(map[string]interface{})["number"])

	// Create network requests concurrently.
	const dnsMessageType = dns.TypeA

	// Obtain all the keys for the targets.
	//targets := []string{"odoh-Target-dot-odoh-Target.wm.r.appspot.com", "odoh-Target-rs.crypto-team.workers.dev"}
	targets := []string{"odoh-Target-rs.crypto-team.workers.dev"}
	//targets := []string{"localhost:8080", "localhost:8787"}
	// TODO(@sudheesh): Discover the targets from a service.
	for _, target := range targets {
		pkbytes, err := RetrievePublicKey(target, state.client)
		if err != nil {
			log.Fatalf("Unable to obtain the public Key from %v. Error %v", target, err)
		}
		state.InsertKey(target, pkbytes)
	}

	keysAvailable := state.TotalNumberOfTargets()
	log.Printf("%v targets available to choose from.", keysAvailable)

	// Part 1 : Initialize and Prepare the Keys to the request.
	symmetricKeys := prepareSymmetricKeys(len(hostnames))
	log.Printf("%v symmetric keys chosen", len(symmetricKeys))

	start := time.Now()
	responseChannel := make(chan Experiment, len(hostnames))
	for index := 0; index < len(hostnames); index++ {
		hostname := hostnames[index]
		key := symmetricKeys[index]
		chosenTarget := targets[mathrand.Intn(keysAvailable)]
		pkOfTarget, err := state.GetPublicKey(chosenTarget)
		if err != nil {
			log.Fatalf("Unable to retrieve the PK requested")
		}
		e := Experiment{
			Hostname:        hostname,
			DnsType:         dnsMessageType,
			Key:             key,
			TargetPublicKey: pkOfTarget,
			Target:          chosenTarget,
			STime:           time.Now(),
		}

		log.Printf("Request %v\n", index)
		go workflow(e, state.client, responseChannel)
	}
	responses := responseHandler(len(hostnames), responseChannel)
	close(responseChannel)

	totalResponse := time.Since(start)
	log.Printf("Time to perform [%v] workflow tasks : [%v]", len(hostnames), totalResponse.Milliseconds())

	log.Printf("Collected [%v] Responses.", len(responses))
	telemetryState.streamDataToElastic(responses)
}