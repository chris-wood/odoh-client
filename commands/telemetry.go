package commands

import (
	"context"
	"encoding/json"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"log"
	"net/http"
	"strings"
	"sync"
)

type telemetry struct {
	sync.RWMutex
	esClient *elasticsearch.Client
}

const (
	INDEX = "telemetry"
	TYPE = "client_localhost"
)

var telemetryInstance telemetry

func getTelemetryInstance() *telemetry {
	elasticsearchTransport := elasticsearch.Config{
		Addresses: []string {
			"http://localhost:9200",
		},
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 1024,
		},
	}
	var err error
	telemetryInstance.esClient, err = elasticsearch.NewClient(elasticsearchTransport)
	if err != nil {
		log.Fatalf("Unable to create an elasticsearch client connection.")
	}
	return &telemetryInstance
}

func (t *telemetry) getClusterInformation() map[string]interface{} {
	var r map[string]interface{}
	res, err := t.esClient.Info()
	if err != nil {
		log.Fatalf("Unable to connect to the elasticsearch instance.")
	}
	defer res.Body.Close()
	if res.IsError() {
		log.Fatalf("Unable to get Response from the elasticsearch instance")
	}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		log.Fatalf("Unable to decode the Response body: %s", err)
	}
	return r
}

func (t *telemetry) streamDataToElastic(dataItems []string) {
	var wg sync.WaitGroup
	for index, item := range dataItems {
		wg.Add(1)
		go func(i int, message string) {
			defer wg.Done()
			req := esapi.IndexRequest{
				Index: INDEX,
				Body: strings.NewReader(message),
				Refresh: "true",
			}

			res, err := req.Do(context.Background(), t.esClient)
			if err != nil {
				log.Printf("Unable to send the request to elastic.")
			}
			defer res.Body.Close()
			if res.IsError() {
				log.Printf("[%s] Error Indexing Value [%s]", res.Status(), message)
			} else {
				log.Printf("Successfully Inserted [%s]", message)
			}
		}(index, item)
	}
	wg.Wait()
}