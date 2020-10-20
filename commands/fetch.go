package commands

import (
	"fmt"
	"github.com/chris-wood/odoh"
	"github.com/urfave/cli"
	"io/ioutil"
	"net/http"
)

func fetchTargetConfig(targetName string, client *http.Client) (odoh.ObliviousDoHConfigs, error) {
	req, err := http.NewRequest(http.MethodGet, TARGET_HTTP_MODE + "://" + targetName + ODOH_CONFIG_WELLKNOWN_URL, nil)
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}

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

func getTargetConfig(c *cli.Context) error {
	client := http.Client{}
	targetName := c.String("target")

	odohConfig, err := fetchTargetConfig(targetName, &client)
	if err != nil {
		return err
	}

	fmt.Printf("%x", odohConfig.Marshal())
	return nil
}
