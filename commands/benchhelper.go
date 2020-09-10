package commands

import (
	"io/ioutil"
	"math/rand"
	"strings"
	"time"
)

func readLines(path string) (lines []string, err error) {
	bytesRead, _ := ioutil.ReadFile(path)
	fileContent := string(bytesRead)
	records := strings.Split(fileContent, "\n")
	return records, nil
}

func shuffleAndSlice(records []string, slice uint64) (lines []string) {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(records), func(i, j int) { records[i], records[j] = records[j], records[i] })
	chosen_records := records[0:slice]
	// Append a '.' to the end of the message for it to be a valid DNS Question about the Hostname
	for index, record := range chosen_records {
		chosen_records[index] = record + "."
	}
	return chosen_records
}
