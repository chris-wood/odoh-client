package commands

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/chris-wood/dns"
	"github.com/chris-wood/odoh"
	"github.com/urfave/cli"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"time"
)

// This runningTime structure contains the epoch timestamps for each of the operations
// taking place. The explanations are as follows:
// 1. Start => Epoch time at which the client starts to prepare the question
// 2. ClientHashingOverheadTime => Epoch time at which the client hashes the symmetric key used for request identification.
// 3. ClientQueryEncryptionTime => Epoch time at which the client completes the encryption and serialization of the question.
// 4. ClientUpstreamRequestTime => Epoch time indicating the start of the network request.
// 5. ClientDownstreamResponseTime => Epoch time indicating the receipt of the response and deserialization into ObliviousDNSMessage
// 6. EndTime => Epoch time indicating the end of all tasks for the request.
// NOTE: All timestamps are stored in NanoSecond granularity and need to be converted into microseconds (/1000.0) or milliseconds (/1000.0^2)
type runningTime struct {
	Start                        int64
	ClientHashingOverheadTime    int64
	ClientQueryEncryptionTime    int64
	ClientUpstreamRequestTime    int64
	ClientDownstreamResponseTime int64
	ClientAnswerDecryptionTime   int64
	EndTime                      int64
}

type experiment struct {
	ExperimentID    string
	Hostname        string
	DnsType         uint16
	Key             []byte
	TargetPublicKey odoh.ObliviousDNSPublicKey
	// Instrumentation
	Proxy  string
	Target string
	// Timing parameters
	IngestedFrom string
	Protocol     string
}

type experimentResult struct {
	Hostname        string
	DnsType         uint16
	Key             []byte
	TargetPublicKey odoh.ObliviousDNSPublicKey
	// Timing parameters
	STime time.Time
	ETime time.Time
	// Instrumentation
	RequestID   string
	DnsQuestion []byte
	DnsAnswer   []byte
	Proxy       string
	Target      string
	Timestamp   runningTime
	// experiment status
	Status       bool
	IngestedFrom string
	ProtocolType string
	ExperimentID string
}

var (
	// DNS constants. Fill in a DNS server to forward to here.
	//resolvers = []string{"cloudflare-dns.com", "dns.google", "dns.quad9.net"}
	resolvers = []string{"cloudflare-dns.com", "dns.google", "dns.quad9.net"}
)

func (e *experimentResult) serialize() string {
	exp := &e
	response, err := json.Marshal(exp)
	if err != nil {
		log.Printf("Unable to log the information correctly.")
	}
	return string(response)
}

type DiscoveryServiceResponse struct {
	Proxies []string `json:"proxies"`
	Targets []string `json:"targets"`
}

func prepareSymmetricKeys(quantity int) [][]byte {
	// Assume that all the keys necessary for the experiment are 16 bytes.
	result := make([][]byte, quantity)
	for i := 0; i < quantity; i++ {
		key := make([]byte, 16)
		_, err := rand.Read(key)
		if err != nil {
			log.Fatalf("Unable to read random bytes to make a symmetric Key.\n")
		}
		result[i] = key
	}
	return result
}

func (e *experiment) run(client *http.Client, channel chan experimentResult) {
	hostname := e.Hostname
	dnsType := e.DnsType
	symmetricKey := e.Key
	targetPublicKey := e.TargetPublicKey
	proxy := e.Proxy
	target := e.Target
	expId := e.ExperimentID
	protocol := e.Protocol

	if protocol == "ODOH" {
		shouldUseProxy := false

		if proxy != "" {
			shouldUseProxy = true
		}

		rt := runningTime{}

		start := time.Now()
		rt.Start = start.UnixNano()
		requestId := sha256.Sum256(symmetricKey)
		hashingTime := time.Now().UnixNano()
		rt.ClientHashingOverheadTime = hashingTime
		serializedODoHQueryMessage, err := prepareOdohQuestion(hostname, dnsType, symmetricKey, targetPublicKey)
		timeToPrepareQuestionAndSerialize := time.Now().UnixNano()
		rt.ClientQueryEncryptionTime = timeToPrepareQuestionAndSerialize
		if err != nil {
			log.Fatalf("Error while preparing OdohQuestion: %v", err)
		}
		requestTime := time.Now().UnixNano()
		rt.ClientUpstreamRequestTime = requestTime
		odohMessage, err := createOdohQueryResponse(serializedODoHQueryMessage, shouldUseProxy, target, proxy, client)

		responseTime := time.Now().UnixNano()
		rt.ClientDownstreamResponseTime = responseTime

		if err != nil || odohMessage == nil {
			exp := experimentResult{
				Hostname:        hostname,
				DnsType:         dnsType,
				Key:             symmetricKey,
				TargetPublicKey: targetPublicKey,
				Target:          target,
				Proxy:           proxy,
				STime:           start,
				ETime:           time.Now(),
				DnsAnswer:       []byte(err.Error()),
				Status:          false,
				Timestamp:       rt,
				IngestedFrom:    e.IngestedFrom,
				ProtocolType:    protocol,
				ExperimentID:    expId,
			}
			channel <- exp
			return
		}
		dnsAnswer, err := validateEncryptedResponse(odohMessage, symmetricKey)
		validationTime := time.Now().UnixNano()
		rt.ClientAnswerDecryptionTime = validationTime
		if err != nil || dnsAnswer == nil {
			exp := experimentResult{
				Hostname:        hostname,
				DnsType:         dnsType,
				Key:             symmetricKey,
				TargetPublicKey: targetPublicKey,
				Target:          target,
				Proxy:           proxy,
				STime:           start,
				ETime:           time.Now(),
				DnsAnswer:       []byte("dnsAnswer incorrectly and unable to Pack"),
				Status:          false,
				Timestamp:       rt,
				IngestedFrom:    e.IngestedFrom,
				ProtocolType:    protocol,
				ExperimentID:    expId,
			}
			channel <- exp
			return
		}
		dnsAnswerBytes, err := dnsAnswer.Pack()
		endTime := time.Now().UnixNano()
		rt.EndTime = endTime

		log.Printf("=======ODOH Request for [%v]========\n", hostname)
		log.Printf("Request ID : [%x]\n", requestId[:])
		log.Printf("Start Time : [%v]\n", start.UnixNano())
		log.Printf("Time @ Hash the Symmetric Key as ID: [%v]\n", hashingTime)
		log.Printf("Time @ Prepare Question and Serialize : [%v]\n", timeToPrepareQuestionAndSerialize)
		log.Printf("Time @ Starting ODOH Request  : [%v]\n", requestTime)
		log.Printf("Time @ Received ODOH Response : [%v]\n", responseTime)
		log.Printf("Time @ Finished Validation Response : [%v]\n", validationTime)
		log.Printf("DNS Answer : [%v]\n", dnsAnswerBytes)
		log.Printf("====================================")
		var requestIDString []byte = requestId[:]
		log.Printf("Requested ID : [%s]", hex.EncodeToString(requestIDString))
		exp := experimentResult{
			Hostname:        hostname,
			DnsType:         dnsType,
			Key:             symmetricKey,
			TargetPublicKey: targetPublicKey,
			// Overall timing parameters
			STime: start,
			ETime: time.Now(),
			// Instrumentation
			RequestID:   hex.EncodeToString(requestIDString),
			DnsQuestion: serializedODoHQueryMessage,
			DnsAnswer:   dnsAnswerBytes,
			Proxy:       proxy,
			Target:      target,
			Timestamp:   rt,
			// experiment status
			Status:       true,
			IngestedFrom: e.IngestedFrom,
			ProtocolType: protocol,
			ExperimentID: expId,
		}
		channel <- exp
	} else if protocol == "DOH" {
		rt := runningTime{}
		start := time.Now()
		requestId := sha256.Sum256(symmetricKey)
		rt.Start = start.UnixNano()
		targetIndex := int(symmetricKey[len(symmetricKey)-1]) % len(resolvers)
		chosenResolver := resolvers[targetIndex]
		hashingTime := time.Now().UnixNano()
		rt.ClientHashingOverheadTime = hashingTime

		serializedDohQuery := prepareDnsQuestion(hostname, dnsType)
		timeToPrepareQuestionAndSerialize := time.Now().UnixNano()
		rt.ClientQueryEncryptionTime = timeToPrepareQuestionAndSerialize

		rt.ClientUpstreamRequestTime = time.Now().UnixNano()
		response, err := createPlainQueryResponse(chosenResolver, serializedDohQuery, "", client)
		rt.ClientDownstreamResponseTime = time.Now().UnixNano()
		if err != nil || response == nil {
			exp := experimentResult{
				Hostname:        hostname,
				DnsType:         dnsType,
				Key:             symmetricKey,
				TargetPublicKey: odoh.ObliviousDNSPublicKey{},
				Target:          chosenResolver,
				Proxy:           "",
				STime:           start,
				ETime:           time.Now(),
				DnsAnswer:       []byte("dnsAnswer incorrectly and unable to Pack"),
				Status:          false,
				Timestamp:       rt,
				IngestedFrom:    e.IngestedFrom,
				ProtocolType:    protocol,
				ExperimentID:    expId,
			}
			channel <- exp
			return
		}

		dnsAnswerBytes, err := response.Pack()
		rt.ClientAnswerDecryptionTime = time.Now().UnixNano()
		endTime := time.Now().UnixNano()
		rt.EndTime = endTime

		var requestIDString []byte = requestId[:]

		exp := experimentResult{
			Hostname:        hostname,
			DnsType:         dnsType,
			Key:             []byte{},
			TargetPublicKey: targetPublicKey,
			// Overall timing parameters
			STime: start,
			ETime: time.Now(),
			// Instrumentation
			RequestID:   hex.EncodeToString(requestIDString),
			DnsQuestion: serializedDohQuery,
			DnsAnswer:   dnsAnswerBytes,
			Proxy:       "NONE-BASELINE-DOH",
			Target:      chosenResolver,
			Timestamp:   rt,
			// experiment status
			Status:       true,
			IngestedFrom: e.IngestedFrom,
			ProtocolType: protocol,
			ExperimentID: expId,
		}
		channel <- exp
	} else if protocol == "pDOH" {
		rt := runningTime{}
		start := time.Now()
		requestId := sha256.Sum256(symmetricKey)
		rt.Start = start.UnixNano()
		targetIndex := int(symmetricKey[len(symmetricKey)-1]) % len(resolvers)
		chosenResolver := resolvers[targetIndex]
		hashingTime := time.Now().UnixNano()
		rt.ClientHashingOverheadTime = hashingTime

		serializedDohQuery := prepareDnsQuestion(hostname, dnsType)
		timeToPrepareQuestionAndSerialize := time.Now().UnixNano()
		rt.ClientQueryEncryptionTime = timeToPrepareQuestionAndSerialize

		rt.ClientUpstreamRequestTime = time.Now().UnixNano()
		response, err := createPlainQueryResponse(chosenResolver, serializedDohQuery, proxy, client)
		rt.ClientDownstreamResponseTime = time.Now().UnixNano()
		if err != nil || response == nil {
			exp := experimentResult{
				Hostname:        hostname,
				DnsType:         dnsType,
				Key:             symmetricKey,
				TargetPublicKey: odoh.ObliviousDNSPublicKey{},
				Target:          chosenResolver,
				Proxy:           proxy,
				STime:           start,
				ETime:           time.Now(),
				DnsAnswer:       []byte("dnsAnswer incorrectly and unable to Pack"),
				Status:          false,
				Timestamp:       rt,
				IngestedFrom:    e.IngestedFrom,
				ProtocolType:    protocol,
				ExperimentID:    expId,
			}
			channel <- exp
			return
		}

		dnsAnswerBytes, err := response.Pack()
		rt.ClientAnswerDecryptionTime = time.Now().UnixNano()
		endTime := time.Now().UnixNano()
		rt.EndTime = endTime

		var requestIDString []byte = requestId[:]

		exp := experimentResult{
			Hostname:        hostname,
			DnsType:         dnsType,
			Key:             []byte{},
			TargetPublicKey: targetPublicKey,
			// Overall timing parameters
			STime: start,
			ETime: time.Now(),
			// Instrumentation
			RequestID:   hex.EncodeToString(requestIDString),
			DnsQuestion: serializedDohQuery,
			DnsAnswer:   dnsAnswerBytes,
			Proxy:       proxy,
			Target:      chosenResolver,
			Timestamp:   rt,
			// experiment status
			Status:       true,
			IngestedFrom: e.IngestedFrom,
			ProtocolType: protocol,
			ExperimentID: expId,
		}
		channel <- exp
	} else if protocol == "CleartextODOH" {
		rt := runningTime{}
		start := time.Now()
		requestId := sha256.Sum256(symmetricKey)
		rt.Start = start.UnixNano()
		hashingTime := time.Now().UnixNano()
		rt.ClientHashingOverheadTime = hashingTime

		serializedDohQuery := prepareDnsQuestion(hostname, dnsType)
		timeToPrepareQuestionAndSerialize := time.Now().UnixNano()
		rt.ClientQueryEncryptionTime = timeToPrepareQuestionAndSerialize

		rt.ClientUpstreamRequestTime = time.Now().UnixNano()
		response, err := createPlainQueryResponse(target, serializedDohQuery, proxy, client)
		rt.ClientDownstreamResponseTime = time.Now().UnixNano()
		if err != nil || response == nil {
			exp := experimentResult{
				Hostname:        hostname,
				DnsType:         dnsType,
				Key:             symmetricKey,
				TargetPublicKey: odoh.ObliviousDNSPublicKey{},
				Target:          target,
				Proxy:           proxy,
				STime:           start,
				ETime:           time.Now(),
				DnsAnswer:       []byte("dnsAnswer incorrectly and unable to Pack"),
				Status:          false,
				Timestamp:       rt,
				IngestedFrom:    e.IngestedFrom,
				ProtocolType:    protocol,
				ExperimentID:    expId,
			}
			channel <- exp
			return
		}

		dnsAnswerBytes, err := response.Pack()
		rt.ClientAnswerDecryptionTime = time.Now().UnixNano()
		endTime := time.Now().UnixNano()
		rt.EndTime = endTime

		var requestIDString []byte = requestId[:]

		exp := experimentResult{
			Hostname:        hostname,
			DnsType:         dnsType,
			Key:             []byte{},
			TargetPublicKey: targetPublicKey,
			// Overall timing parameters
			STime: start,
			ETime: time.Now(),
			// Instrumentation
			RequestID:   hex.EncodeToString(requestIDString),
			DnsQuestion: serializedDohQuery,
			DnsAnswer:   dnsAnswerBytes,
			Proxy:       proxy,
			Target:      target,
			Timestamp:   rt,
			// experiment status
			Status:       true,
			IngestedFrom: e.IngestedFrom,
			ProtocolType: protocol,
			ExperimentID: expId,
		}
		channel <- exp
	} else if protocol == "DOHOT" {
		rt := runningTime{}
		start := time.Now()
		requestId := sha256.Sum256(symmetricKey)
		rt.Start = start.UnixNano()

		targetIndex := int(symmetricKey[len(symmetricKey)-1]) % len(resolvers)
		chosenResolver := resolvers[targetIndex]

		hashingTime := time.Now().UnixNano()
		rt.ClientHashingOverheadTime = hashingTime

		serializedDohQuery := prepareDnsQuestion(hostname, dnsType)
		timeToPrepareQuestionAndSerialize := time.Now().UnixNano()
		rt.ClientQueryEncryptionTime = timeToPrepareQuestionAndSerialize

		rt.ClientUpstreamRequestTime = time.Now().UnixNano()
		response, err := createPlainQueryResponse(chosenResolver, serializedDohQuery, "", client)
		rt.ClientDownstreamResponseTime = time.Now().UnixNano()

		if err != nil || response == nil {
			exp := experimentResult{
				Hostname:        hostname,
				DnsType:         dnsType,
				Key:             symmetricKey,
				TargetPublicKey: odoh.ObliviousDNSPublicKey{},
				Target:          chosenResolver,
				Proxy:           "",
				STime:           start,
				ETime:           time.Now(),
				DnsAnswer:       []byte("dnsAnswer incorrectly and unable to Pack"),
				Status:          false,
				Timestamp:       rt,
				IngestedFrom:    e.IngestedFrom,
				ProtocolType:    protocol,
				ExperimentID:    expId,
			}
			channel <- exp
			return
		}

		dnsAnswerBytes, err := response.Pack()
		rt.ClientAnswerDecryptionTime = time.Now().UnixNano()
		endTime := time.Now().UnixNano()
		rt.EndTime = endTime

		var requestIDString []byte = requestId[:]

		exp := experimentResult{
			Hostname:        hostname,
			DnsType:         dnsType,
			Key:             []byte{},
			TargetPublicKey: targetPublicKey,
			// Overall timing parameters
			STime: start,
			ETime: time.Now(),
			// Instrumentation
			RequestID:   hex.EncodeToString(requestIDString),
			DnsQuestion: serializedDohQuery,
			DnsAnswer:   dnsAnswerBytes,
			Proxy:       "NONE-BASELINE-DOHOT",
			Target:      chosenResolver,
			Timestamp:   rt,
			// experiment status
			Status:       true,
			IngestedFrom: e.IngestedFrom,
			ProtocolType: protocol,
			ExperimentID: expId,
		}
		log.Printf("experiment : %v", exp.serialize())
		channel <- exp
	} else if protocol == "DNSCrypt" {
		dnsCryptHost := "127.0.0.1:53"
		rt := runningTime{}
		start := time.Now()
		rt.Start = start.UnixNano()
		query := new(dns.Msg)
		rt.ClientHashingOverheadTime = time.Now().UnixNano()
		query.SetQuestion(hostname, dnsType)
		rt.ClientQueryEncryptionTime = time.Now().UnixNano()

		connection := new(dns.Conn)
		rt.ClientUpstreamRequestTime = time.Now().UnixNano()
		var err error
		if connection.Conn, err = net.DialTimeout("tcp", dnsCryptHost, 2500*time.Millisecond); err != nil {
			exp := experimentResult{
				Hostname:        hostname,
				DnsType:         dnsType,
				Key:             symmetricKey,
				TargetPublicKey: odoh.ObliviousDNSPublicKey{},
				Target:          dnsCryptHost,
				Proxy:           "",
				STime:           start,
				ETime:           time.Now(),
				DnsAnswer:       []byte(err.Error()),
				Status:          false,
				Timestamp:       rt,
				IngestedFrom:    e.IngestedFrom,
				ProtocolType:    protocol,
				ExperimentID:    expId,
			}
			channel <- exp
			return
		}

		connection.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
		connection.SetWriteDeadline(time.Now().Add(2500 * time.Millisecond))

		if err := connection.WriteMsg(query); err != nil {
			exp := experimentResult{
				Hostname:        hostname,
				DnsType:         dnsType,
				Key:             symmetricKey,
				TargetPublicKey: odoh.ObliviousDNSPublicKey{},
				Target:          dnsCryptHost,
				Proxy:           "",
				STime:           start,
				ETime:           time.Now(),
				DnsAnswer:       []byte("dnsAnswer incorrectly and unable to Pack"),
				Status:          false,
				Timestamp:       rt,
				IngestedFrom:    e.IngestedFrom,
				ProtocolType:    protocol,
				ExperimentID:    expId,
			}
			channel <- exp
			return
		}

		response, err := connection.ReadMsg()
		rt.ClientDownstreamResponseTime = time.Now().UnixNano()
		if err != nil {
			exp := experimentResult{
				Hostname:        hostname,
				DnsType:         dnsType,
				Key:             symmetricKey,
				TargetPublicKey: odoh.ObliviousDNSPublicKey{},
				Target:          dnsCryptHost,
				Proxy:           "",
				STime:           start,
				ETime:           time.Now(),
				DnsAnswer:       []byte("dnsAnswer unable to Read"),
				Status:          false,
				Timestamp:       rt,
				IngestedFrom:    e.IngestedFrom,
				ProtocolType:    protocol,
				ExperimentID:    expId,
			}
			channel <- exp
			return
		}

		rt.ClientAnswerDecryptionTime = time.Now().UnixNano()

		response.Id = query.Id

		responseBytes, err := response.Pack()
		if err != nil {
			exp := experimentResult{
				Hostname:        hostname,
				DnsType:         dnsType,
				Key:             symmetricKey,
				TargetPublicKey: odoh.ObliviousDNSPublicKey{},
				Target:          dnsCryptHost,
				Proxy:           "",
				STime:           start,
				ETime:           time.Now(),
				DnsAnswer:       []byte("Failed to Pack the DNSAnswer"),
				Status:          false,
				Timestamp:       rt,
				IngestedFrom:    e.IngestedFrom,
				ProtocolType:    protocol,
				ExperimentID:    expId,
			}
			channel <- exp
			return
		}

		rt.EndTime = time.Now().UnixNano()

		exp := experimentResult{
			Hostname:        hostname,
			DnsType:         dnsType,
			Key:             symmetricKey,
			TargetPublicKey: odoh.ObliviousDNSPublicKey{},
			Target:          dnsCryptHost,
			Proxy:           "",
			STime:           start,
			ETime:           time.Now(),
			DnsAnswer:       responseBytes,
			Status:          true,
			Timestamp:       rt,
			IngestedFrom:    e.IngestedFrom,
			ProtocolType:    protocol,
			ExperimentID:    expId,
		}
		channel <- exp
	} else {
		log.Fatalf("No Known Protocol Experiment to Run.")
	}
}

func responseHandler(numberOfChannels int, responseChannel chan experimentResult) []string {
	responses := make([]string, 0)
	for index := 0; index < numberOfChannels; index++ {
		answerStructure := <-responseChannel
		answer := answerStructure.DnsAnswer
		sTime := answerStructure.STime
		eTime := answerStructure.ETime
		hostname := answerStructure.Hostname
		target := answerStructure.Target
		proxy := answerStructure.Proxy
		log.Printf("Response %v\n", index)
		log.Printf("Size of the Response for [%v] is [%v] and [%v] to [%v] = [%v] using Proxy [%v] using Target [%v]",
			hostname, len(answer), sTime.UnixNano(), eTime.UnixNano(), eTime.Sub(sTime).Microseconds(), proxy, target)
		responses = append(responses, answerStructure.serialize())
	}
	return responses
}

func getTickTriggerTiming(requestsPerMinute int) float64 {
	intervalDuration := time.Minute.Seconds() / float64(requestsPerMinute)
	return intervalDuration
}

/*
The benchmarkClient creates `--numclients` client instances performing `--pick` queries over `--rate` requests/minute
uniformly distributed.
*/
func benchmarkClient(c *cli.Context) {
	var clientInstanceName string
	if clientInstanceEnvironmentName := os.Getenv("CLIENT_INSTANCE_NAME"); clientInstanceEnvironmentName != "" {
		clientInstanceName = clientInstanceEnvironmentName
	} else {
		clientInstanceName = "client_localhost_instance"
	}

	var experimentID string
	if experimentID := os.Getenv("EXPERIMENT_ID"); experimentID == "" {
		experimentID = "EXP_LOCAL"
	}

	outputFilePath := c.String("out")
	f, err := os.OpenFile(outputFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Unable to create a log file to log data into.")
	}
	defer f.Close()
	log.SetOutput(f)

	// The Preparation Phase of the request.
	filepath := c.String("data")
	filterCount := c.Uint64("pick")
	numberOfParallelClients := c.Uint64("numclients")
	requestPerMinute := c.Uint64("rate") // requests/minute
	discoveryServiceHostname := c.String("discovery")
	protocol := c.String("protocol")
	tickTrigger := getTickTriggerTiming(int(requestPerMinute))
	ingestionMode := c.String("ingest")
	ingestionElkUrl := c.String("elkurl")
	gcpProjectID := c.String("gcpproject")
	gcpLoggingName := c.String("gcplogname")

	telemetryConfig := make(map[string]string)
	telemetryConfig["ingest"] = ingestionMode
	if ingestionMode == "GCP" {
		telemetryConfig["gcpProjectId"] = gcpProjectID
		telemetryConfig["gcpLoggingName"] = gcpLoggingName
	} else if ingestionMode == "ELK" {
		telemetryConfig["elkurl"] = ingestionElkUrl
	}

	totalResponsesNeeded := numberOfParallelClients * filterCount

	allDomains, err := readLines(filepath)

	if err != nil {
		log.Printf("Failed to read the file correctly. %v", err)
	}

	hostnames := shuffleAndSlice(allDomains, filterCount)
	log.Printf("Now operating on a total size of : [%v] hostnames", len(hostnames))

	// Create a base state of the experiment
	telemetryState := getTelemetryInstance(telemetryConfig)
	state := GetInstance(numberOfParallelClients)
	if protocol == "DOHOT" {
		state = UpdateClientsToTorClients("localhost", 9050)
	}
	//telemetryResponse := telemetryState.getClusterInformation()
	//log.Printf("Server: %s", telemetryResponse["version"].(map[string]interface{})["number"])

	// Create network requests concurrently.
	const dnsMessageType = dns.TypeA

	availableServices, err := DiscoverProxiesAndTargets(discoveryServiceHostname, instance.baseClient)
	if err != nil {
		log.Fatalf("Unable to discover the services available.")
	}

	// Obtain all the keys for the targets.
	targets := availableServices.Targets
	proxies := availableServices.Proxies
	for _, target := range targets {
		pkbytes, err := RetrievePublicKey(target, instance.baseClient)
		if err != nil {
			log.Fatalf("Unable to obtain the public Key from %v. Error %v", target, err)
		}
		state.InsertKey(target, pkbytes)
	}

	var proxyWithLowestLatency string
	var targetWithLowestLatency string
	var LatencyMin int64
	LatencyMin = math.MaxInt64

	for _, target := range targets {
		for _, proxy := range proxies {
			start := time.Now().UnixNano()
			pk, err := state.GetPublicKey(target)
			respBytes, err := QueryProxyTargetTime(proxy, target, pk, instance.baseClient)
			if err != nil {
				log.Fatalf("Unable to reach the queries.")
			}
			end := time.Now().UnixNano()
			totalTime := (end - start) / (1000.0 * 1000.0)
			log.Printf("[%v] [%v] : %v ms of size %v\n", proxy, target, totalTime, len(respBytes))
			if totalTime < LatencyMin {
				LatencyMin = totalTime
				proxyWithLowestLatency = proxy
				targetWithLowestLatency = target
			}
		}
	}

	log.Printf("Target and Proxy with lowest latency : %v ms [%v][%v]\n", LatencyMin, targetWithLowestLatency, proxyWithLowestLatency)

	keysAvailable := state.TotalNumberOfTargets()
	log.Printf("%v targets available to choose from.", keysAvailable)
	log.Printf("%v proxies available to choose from.", len(proxies))

	// Part 1 : Initialize and Prepare the Keys to the request.
	symmetricKeys := prepareSymmetricKeys(len(hostnames))
	log.Printf("%v symmetric keys chosen", len(symmetricKeys))

	start := time.Now()
	responseChannel := make(chan experimentResult, totalResponsesNeeded)

	totalQueries := len(hostnames)
	log.Printf("Tick Trigger : %v %v", tickTrigger, time.Duration(tickTrigger)*time.Minute)

	requestPerMinuteTick := time.NewTicker(time.Duration(tickTrigger) * time.Second)

	for now := range requestPerMinuteTick.C {
		log.Printf("[%v] Firing %v requests at %v\n", totalQueries, requestPerMinute, now)
		startIndex := totalQueries - 1
		endIndex := startIndex - int(requestPerMinute)
		if endIndex < 0 {
			endIndex = 0
		}
		for index := startIndex; index >= endIndex; index-- {
			for clientIndex := 0; clientIndex < int(numberOfParallelClients); clientIndex++ {
				hostname := hostnames[index]
				key := symmetricKeys[index]
				clientUsed := state.client[clientIndex]
				log.Printf("Choosing [Client %v] to make a query", index%int(numberOfParallelClients))
				// Code fix defaults to pick Proxy/Target as the ones with the lowest latency. For randomizing use the
				// commented section of the code in the next two lines to choose random target and proxies.
				chosenTarget := targetWithLowestLatency //  targets[mathrand.Intn(keysAvailable)]
				chosenProxy := proxyWithLowestLatency   // proxies[mathrand.Intn(len(proxies))]
				pkOfTarget, err := state.GetPublicKey(chosenTarget)
				if err != nil {
					log.Fatalf("Unable to retrieve the PK requested")
				}
				e := experiment{
					ExperimentID:    experimentID,
					Hostname:        hostname,
					DnsType:         dnsMessageType,
					Key:             key,
					TargetPublicKey: pkOfTarget,
					Target:          chosenTarget,
					Proxy:           chosenProxy,
					IngestedFrom:    clientInstanceName,
					Protocol:        protocol,
				}

				log.Printf("Request %v%v\n", index, clientIndex)
				go e.run(clientUsed, responseChannel)
			}
			totalQueries--
		}
		if totalQueries <= 0 {
			log.Printf("Breaking out of the request per minute loop.")
			requestPerMinuteTick.Stop()
			break
		}
	}
	log.Printf("Reached here and triggering the responseHandler.\n")
	responses := responseHandler(int(totalResponsesNeeded), responseChannel)
	close(responseChannel)

	totalResponse := time.Since(start)
	log.Printf("Time to perform [%v] workflow tasks : [%v]", len(hostnames), totalResponse.Milliseconds())

	if ingestionMode == "GCP" {
		log.Printf("Collected [%v] Responses.", len(responses))
		telemetryState.streamLogsToGCP(responses)
		telemetryState.tearDown()
	} else if ingestionMode == "ELK" {
		telemetryState.streamLogsToELK(responses)
	}
}
