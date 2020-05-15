package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/Jeffail/gabs/v2"
)

// IPAddress  -

var (
	IPAddress      = flag.String("ip", "", "IP Address")
	flagMaltego    = flag.Bool("maltego", false, "Generate maltego transform response")
	entityTemplate = `
	<Entity Type="anubis.Risk">
	<Value>DATA</Value>
	<Weight>100</Weight>
	</Entity>
	`
	maltegoMessageTemplate = `
	<MaltegoMessage>
	<MaltegoTransformResponseMessage>
	<Entities>
		MALTEGO_ENTITY
	</Entities>
	</MaltegoTransformResponseMessage>
	</MaltegoMessage>
	`
)

type anubisRequest struct {
	IPAddress string
}

func main() {
	flag.Parse()

	if *IPAddress != "" {
		httpClient := http.Client{}
		requestBody, _ := json.Marshal(anubisRequest{IPAddress: *IPAddress})
		requestURL := "https://intel.malwareroulette.io/anubis/ip"
		requestReader := bytes.NewReader(requestBody)
		httpRequest, err := http.NewRequest("POST", requestURL, requestReader)
		httpRequest.Header.Add("user-agent", "Anubis CLI")
		httpRequest.Header.Add("Content-Type", "application/json")

		httpResponse, err := httpClient.Do(httpRequest)
		responseBytes := httpResponse.Body
		message, err := ioutil.ReadAll(responseBytes)
		prettyPrint, err := gabs.ParseJSON(message)

		if err != nil {
			log.Fatal("", string(message), err)
		}
		response := string(prettyPrint.String())
		if !*flagMaltego {
			fmt.Println(response)
		} else {
			RiskRating := prettyPrint.Search("RiskRating").Data().(string)
			ResponseEntity := strings.Replace(entityTemplate, "DATA", RiskRating, 1)
			ResponseMessage := strings.Replace(maltegoMessageTemplate, "MALTEGO_ENTITY", ResponseEntity, 1)
			fmt.Println(ResponseMessage)
		}
	} else {
		flag.Usage()
	}

}
