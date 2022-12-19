package ping

import (
	"log"
	"net"
	"os"
	"sync"
)

type Ping struct {
	PeerAddr string
	Internal uint64
	ForceV4  bool
	ForceV6  bool

	id   uint16
	wg   sync.WaitGroup
	addr *net.IPAddr
	conn *net.IPConn
}

func (server *Ping) ListenAndServe() {
	server.id = uint16(os.Getpid())

	nw := "ip"
	if server.ForceV4 {
		nw = "ip4"
	}
	if server.ForceV6 {
		nw = "ip6"
	}

	addr, err := net.ResolveIPAddr(nw, server.PeerAddr)
	if err != nil {
		log.Println(err)
		return
	}
	server.addr = addr

	if addr.IP.To4() != nil {
		log.Printf("target v4: %v", addr)
		server.listenAndServe4()
	} else {
		log.Printf("target v6: %v", addr)
		server.listenAndServer6()
	}
}
