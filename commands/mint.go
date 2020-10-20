package commands

import (
	"os"
	"log"
	"crypto/rand"
	"strconv"
	"encoding/pem"
	"github.com/urfave/cli"
	"github.com/chris-wood/odoh"
	hpke "github.com/cisco/go-hpke"
)

func createConfigurations(c *cli.Context) error {
	kemID, err := strconv.ParseUint(c.String("kemid"), 10, 16)
	if err != nil {
		return err
	}
	kdfID, err := strconv.ParseUint(c.String("kdfid"), 10, 16)
	if err != nil {
		return err
	}
	aeadID, err := strconv.ParseUint(c.String("aeadid"), 10, 16)
	if err != nil {
		return err
	}

	suite, err := hpke.AssembleCipherSuite(hpke.KEMID(kemID), hpke.KDFID(kdfID), hpke.AEADID(aeadID))
	if err != nil {
		return err
	}

	ikm := make([]byte, suite.KEM.PrivateKeySize())
	rand.Reader.Read(ikm)
	privateKey, publicKey, err := suite.KEM.DeriveKeyPair(ikm)
	if err != nil {
		return err
	}

	configContents, err := odoh.CreateObliviousDoHConfigContents(hpke.KEMID(kemID), hpke.KDFID(kdfID), hpke.AEADID(aeadID), suite.KEM.Serialize(publicKey))
	if err != nil {
		return err
	}

	config := odoh.CreateObliviousDoHConfig(configContents)
	configs := odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{config})

	configsBlock := &pem.Block{
		Type: "ODOH CONFIGS",
		Bytes: configs.Marshal(),
	}
	if err := pem.Encode(os.Stdout, configsBlock); err != nil {
		log.Fatal(err)
	}

	privateConfigsBlock := &pem.Block{
		Type: "ODOH PRIVATE KEY",
		Bytes: suite.KEM.SerializePrivate(privateKey),
	}
	if err := pem.Encode(os.Stdout, privateConfigsBlock); err != nil {
		log.Fatal(err)
	}

	return nil
}