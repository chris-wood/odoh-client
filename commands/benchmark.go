package commands

import (
	"crypto/rand"
	"crypto/sha256"
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
	hostname string
	dnsType uint16
	key []byte
	targetPublicKey odoh.ObliviousDNSPublicKey
	target string
	// Timing parameters
	sTime time.Time
	eTime time.Time
	response []byte
}

func prepareSymmetricKeys(quantity int) [][]byte {
	// Assume that all the keys necessary for the experiment are 16 bytes.
	result := make([][]byte, quantity)
	start := time.Now()
	for i := 0; i < quantity; i++ {
		key := make([]byte, 16)
		_, err := rand.Read(key)
		if err != nil {
			log.Fatalf("Unable to read random bytes to make a symmetric key.\n")
		}
		result[i] = key
	}
	log.Printf("Time (ms) to generate %v symmetric keys : [%v]", len(result), time.Since(start).Microseconds())
	return result
}

//func worker(id int, experiment Experiment) {
//	log.Printf("Request %v\n", id)
//	s := time.Now()
//	go workflow(experiment.hostname, experiment.dnsType, experiment.key, experiment.targetPublicKey, experiment.target, responseChannel)
//	e := time.Now()
//	log.Printf("Response %v\n", id)
//	log.Printf("Size of the Response for [%v] is [%v] and [%v] to [%v] = [%v] using target [%v]", experiment.hostname, len(answer), s.UnixNano(), e.UnixNano(), e.Sub(s).Microseconds(), experiment.target)
//}

func workflow(e Experiment, client *http.Client, channel chan Experiment) {
	hostname := e.hostname
	dnsType := e.dnsType
	symmetricKey := e.key
	targetPublicKey := e.targetPublicKey
	target := e.target

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
			hostname:        hostname,
			dnsType:         dnsType,
			key:             symmetricKey,
			targetPublicKey: targetPublicKey,
			target:          target,
			sTime:           e.sTime,
			eTime:           time.Now(),
			response:        []byte(err.Error()),
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
		hostname:        hostname,
		dnsType:         dnsType,
		key:             symmetricKey,
		targetPublicKey: targetPublicKey,
		target:          target,
		sTime:           e.sTime,
		eTime:           time.Now(),
		response:        dnsAnswerBytes,
	}
	channel <- exp
}

func responseHandler(numberOfChannels int, responseChannel chan Experiment) {
	for index := 0; index < numberOfChannels; index++ {
		answerStructure := <- responseChannel
		answer := answerStructure.response
		sTime := answerStructure.sTime
		eTime := answerStructure.eTime
		hostname := answerStructure.hostname
		target := answerStructure.target
		log.Printf("Response %v\n", index)
		log.Printf("Size of the Response for [%v] is [%v] and [%v] to [%v] = [%v] using target [%v]", hostname, len(answer), sTime.UnixNano(), eTime.UnixNano(), eTime.Sub(sTime).Microseconds(), target)
	}
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

	// Create network requests concurrently.
	const dnsMessageType = dns.TypeA

	// Obtain all the keys for the targets.
	//targets := []string{"odoh-target-dot-odoh-target.wm.r.appspot.com", "odoh-target-rs.crypto-team.workers.dev"}
	targets := []string{"odoh-target-rs.crypto-team.workers.dev"}
	//targets := []string{"localhost:8080", "localhost:8787"}
	// TODO(@sudheesh): Discover the targets from a service.
	for _, target := range targets {
		pkbytes, err := RetrievePublicKey(target, state.client)
		if err != nil {
			log.Fatalf("Unable to obtain the public key from %v. Error %v", target, err)
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
			hostname:        hostname,
			dnsType:         dnsMessageType,
			key:             key,
			targetPublicKey: pkOfTarget,
			target:          chosenTarget,
			sTime: time.Now(),
		}

		log.Printf("Request %v\n", index)
		go workflow(e, state.client, responseChannel)
	}
	responseHandler(len(hostnames), responseChannel)
	close(responseChannel)

	totalResponse := time.Since(start)
	log.Printf("Time to perform [%v] workflow tasks : [%v]", len(hostnames), totalResponse.Milliseconds())
}