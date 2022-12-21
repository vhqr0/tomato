package main

import (
	"flag"

	"github.com/vhqr0/tomato/vpn"
)

var (
	verbose   = flag.Bool("v", false, "verbose trace info")
	dynupdate = flag.Bool("d", false, "dynamic update peer address")
	iface     = flag.String("I", "tun0", "tun interface name")
	localaddr = flag.String("la", "", "local address")
	localpwd  = flag.String("lp", "", "local password")
	peeraddr  = flag.String("pa", "", "peer address")
	peerpwd   = flag.String("pp", "", "peer password")
	pktvt     = flag.Uint64("pvt", 10, "peer packet valid time")
	addrvt    = flag.Uint64("avt", 60, "peer address valid time")
)

func main() {
	flag.Parse()

	server := vpn.Vpn{
		LogTrace:      *verbose,
		DynUpdate:     *dynupdate,
		Iface:         *iface,
		LocalAddr:     *localaddr,
		LocalPwd:      *localpwd,
		PeerAddr:      *peeraddr,
		PeerPwd:       *peerpwd,
		PktValidTime:  *pktvt,
		AddrValidTime: *addrvt,
	}
	server.ListenAndServe()
}
