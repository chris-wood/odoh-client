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
			cli.StringFlag{
				Name: "target",
				Value: "localhost:8080",
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
				Name: "proxy, p",
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
	{
		Name: "bench",
		Usage: "Performs a benchmark for ODOH Target Resolver",
		Action: benchmarkClient,
		Flags: []cli.Flag {
			cli.StringFlag{
				Name: "data",
				Value: "dataset.csv",
			},
			cli.Uint64Flag{
				Name: "pick",
				Value: 10,
			},
			cli.Uint64Flag{
				Name: "numclients",
				Value: 10,
			},
			cli.Uint64Flag{
				Name: "rate", // We default to the rate per minute. Please provide this rate in req/min to make.
				Value: 15,
			},
			cli.StringFlag{
				Name: "out",
				Value: "data/data-test.txt",
			},
			cli.StringFlag{
				Name: "discovery",
				Value: "odoh-discovery.crypto-team.workers.dev",
			},
		},
	},
}