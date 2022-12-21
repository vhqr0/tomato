package ping

import (
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"os"
	"time"
)

type Ping struct {
	Addr     string
	ForceV4  bool
	ForceV6  bool
	Internal uint64

	id      uint16
	reqType byte
	repType byte
	conn    *net.IPConn
}

func (server *Ping) sender() {
	var buf [256]byte

	rand.Seed(time.Now().Unix())

	tick := time.Tick(time.Duration(server.Internal) * time.Second)

	for seq := uint16(0); ; seq++ {
		<-tick

		n := (rand.Int() % 248) + 8

		buf[0] = server.reqType // type
		buf[1] = 0              // code
		buf[2] = 0              // checksum[0]
		buf[3] = 0              // checksum[1]
		if _, err := rand.Read(buf[8:n]); err != nil {
			log.Fatal(err)
		}
		binary.BigEndian.PutUint16(buf[4:6], server.id)
		binary.BigEndian.PutUint16(buf[6:8], seq)

		if server.reqType == ICMP_ECHO_REQUEST {
			binary.BigEndian.PutUint16(buf[2:4], checkSum(buf[:n]))
		}

		if _, err := server.conn.Write(buf[:n]); err != nil {
			log.Fatal(err)
		}
		log.Printf("ping seq %d, len %d", seq, n)
	}
}

func (server *Ping) receiver() {
	var buf [4096]byte

	for {
		n, err := server.conn.Read(buf[:])
		if err != nil {
			log.Fatal(err)
		}

		var icmpBuf []byte
		if server.repType == ICMP_ECHO_REPLY {
			icmpBuf = getIcmpBuf(buf[:n])
		} else {
			icmpBuf = buf[:n]
		}
		if len(icmpBuf) < 8 {
			continue
		}

		typ := icmpBuf[0]
		code := icmpBuf[1]
		id := binary.BigEndian.Uint16(icmpBuf[4:6])
		seq := binary.BigEndian.Uint16(icmpBuf[6:8])
		if typ != server.repType || code != 0 || id != server.id {
			continue
		}
		log.Printf("pong seq %d, len %d", seq, len(icmpBuf))
	}
}

func (server *Ping) ListenAndServe() {
	server.id = uint16(os.Getpid())

	network := "ip"
	if server.ForceV4 {
		network = "ip4"
	}
	if server.ForceV6 {
		network = "ip6"
	}

	addr, err := net.ResolveIPAddr(network, server.Addr)
	if err != nil {
		log.Fatal(err)
	}

	if addr.IP.To4() != nil {
		log.Printf("target v4: %v", addr)
		network = "ip4:icmp"
		server.reqType = ICMP_ECHO_REQUEST
		server.repType = ICMP_ECHO_REPLY
	} else {
		log.Printf("target v6: %v", addr)
		network = "ip6:ipv6-icmp"
		server.reqType = ICMP6_ECHO_REQUEST
		server.repType = ICMP6_ECHO_REPLY
	}

	conn, err := net.DialIP(network, nil, addr)
	if err != nil {
		log.Fatal(err)
	}
	server.conn = conn

	if server.reqType == ICMP6_ECHO_REQUEST {
		filter := icmp6Filter{}
		filter.setBlockAll()
		filter.setPass(ICMP6_ECHO_REPLY)
		if err := filter.setConnOpt(conn); err != nil {
			log.Fatal(err)
		}
	}

	go server.receiver()
	server.sender()
}
