package main

import (
	"flag"
	"log"

	"github.com/vhqr0/tomato/ping"
	"github.com/vhqr0/tomato/proxy"
	"github.com/vhqr0/tomato/vpn"
)

var (
	command   = flag.String("c", "proxy", "command: proxy/vpn/ping")
	iface     = flag.String("if", "tun0", "tun interface")
	localaddr = flag.String("la", ":1080", "local address")
	peeraddr  = flag.String("pa", ":1080", "peer address")
	localpwd  = flag.String("lp", "", "local password")
	peerpwd   = flag.String("pp", "", "peer password")
	rulemode  = flag.String("rm", "direct", "rule mode")
	rulefile  = flag.String("rf", "", "rule db file")
	internal  = flag.Uint64("it", 30, "ping internal")
	pktvt     = flag.Uint64("pvt", 10, "peer packet valid time")
	addrvt    = flag.Uint64("avt", 60, "peer address valid time")
	dynupdate = flag.Bool("du", false, "dynamic update peer address")
	forward   = flag.Bool("fw", false, "forward proxy request")
	forcev4   = flag.Bool("4", false, "force use IPv4")
	forcev6   = flag.Bool("6", false, "force use IPv6")
	verbose   = flag.Bool("v", false, "verbose trace info")
)

func main() {
	flag.Parse()

	switch *command {
	case "proxy":
		server := proxy.Proxy{
			LogTrace:  *verbose,
			Forward:   *forward,
			RuleMode:  *rulemode,
			RuleFile:  *rulefile,
			LocalAddr: *localaddr,
			PeerAddr:  *peeraddr,
		}
		server.ListenAndServe()
	case "vpn":
		server := vpn.Vpn{
			LogTrace:      *verbose,
			DynUpdate:     *dynupdate,
			Iface:         *iface,
			LocalAddr:     *localaddr,
			PeerAddr:      *peeraddr,
			LocalPwd:      *localpwd,
			PeerPwd:       *peerpwd,
			PktValidTime:  *pktvt,
			AddrValidTime: *addrvt,
		}
		server.ListenAndServe()
	case "ping":
		server := ping.Ping{
			PeerAddr: *peeraddr,
			Internal: *internal,
			ForceV4:  *forcev4,
			ForceV6:  *forcev6,
		}
		server.ListenAndServe()
	default:
		log.Fatal("unrecognized command: " + *command)
	}
}
