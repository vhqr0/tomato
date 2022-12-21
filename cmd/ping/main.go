package main

import (
	"flag"

	"github.com/vhqr0/tomato/ping"
)

var (
	addr     = flag.String("a", "localhost", "ping target address")
	forcev4  = flag.Bool("4", false, "ping target force IPv4")
	forcev6  = flag.Bool("6", false, "ping target force IPv6")
	internal = flag.Uint64("i", 30, "ping internal")
)

func main() {
	flag.Parse()
	server := ping.Ping{
		Addr:     *addr,
		ForceV4:  *forcev4,
		ForceV6:  *forcev6,
		Internal: *internal,
	}
	server.ListenAndServe()
}
