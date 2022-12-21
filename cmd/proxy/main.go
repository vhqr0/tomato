package main

import (
	"flag"

	"github.com/vhqr0/tomato/proxy"
)

var (
	verbose     = flag.Bool("v", false, "verbose trace info")
	localaddr   = flag.String("l", ":1080", "local proxy address")
	forwardaddr = flag.String("f", "", "forward proxy address")
	direction   = flag.String("d", "direct", "direction: block/direct/forward")
	rulefile    = flag.String("r", "", "rule db file")
)

func main() {
	flag.Parse()

	server := proxy.Proxy{
		LogTrace:    *verbose,
		LocalAddr:   *localaddr,
		ForwardAddr: *forwardaddr,
		Direction:   *direction,
		RuleFile:    *rulefile,
	}
	server.ListenAndServe()
}
