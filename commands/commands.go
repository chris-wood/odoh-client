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
			},
			cli.StringFlag{
				Name:  "dnstype, t",
				Value: "AAAA",
			},
			cli.StringFlag{
				Name: "keyID, k",
				Value: "0000",
			},
		},
	},
}