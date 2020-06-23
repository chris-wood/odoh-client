module github.com/chris-wood/odoh-client

go 1.14

require (
	github.com/chris-wood/dns v0.0.0-20161202223856-f4d2b086946a
	github.com/chris-wood/odoh v0.0.0-20200619224544-8cfb1f9f3228
	github.com/miekg/dns v1.1.29 // indirect
	github.com/urfave/cli v1.22.4
)

replace github.com/chris-wood/odoh => ../odoh
