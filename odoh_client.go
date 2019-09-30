package main

import (
	"log"

	"github.com/babolivier/go-doh-client"
)

func main() {
	resolver := doh.Resolver{
		Host: "localhost",
		Class: doh.IN,
	}

	a, _, err := resolver.LookupA("apple.com")
	if err != nil {
		panic(err)
	}
	println(a[0].IP4)
}