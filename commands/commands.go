package commands

import (
	"github.com/urfave/cli"
)

var Commands = []cli.Command{
	{
		Name:   "doh",
		Usage:  "A plain application/dns-message request",
		Action: plainDnsRequest,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "domain, d",
				Value: "www.cloudflare.com.",
			},
			cli.StringFlag{
				Name:  "dnstype, t",
				Value: "AAAA",
			},
		},
	},
	{
		Name: "odoh",
		Usage: "An oblivious application/oblivious-dns-message request",
		Action: obliviousDnsRequest,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "domain, d",
				Value: "www.cloudflare.com.",
				Usage: "Domain name which needs to be resolved. Use trailing period (.).",
			},
			cli.StringFlag{
				Name:  "dnstype, t",
				Value: "AAAA",
				Usage: "Type of DNS Question. Currently supports A, AAAA, CAA, CNAME",
			},
			cli.StringFlag{
				Name: "target",
				Value: "localhost:8080",
				Usage: "Hostname:Port format declaration of the target resolver hostname",
			},
			cli.StringFlag{
				Name: "key, k",
				Value: "00000000000000000000000000000000",  // 16 bytes or 32 byte hex string
				Usage: "Hex Encoded String containing the Symmetric Key which is used to return an Encrypted Response",
			},
			cli.BoolFlag{
				Name:        "use-proxy, up",
				Usage:       "Boolean True/False value to set with proxy",
				Required:    false,
				Hidden:      false,
			},
			cli.StringFlag{
				Name: "proxy, p",
				Value: "localhost:8080",
				Usage: "Hostname:Port format declaration of the proxy hostname",
			},
		},
	},
	{
		Name: "get-publickey",
		Usage: "Retrieves the public key of the target resolver",
		Action: getTargetPublicKey,
		Flags: []cli.Flag {
			cli.StringFlag{
				Name: "ip",
				Value: "localhost:8080",
			},
		},
	},
}