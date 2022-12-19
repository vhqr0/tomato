package ping

import (
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"syscall"
	"time"
)

// see /usr/include/netinet/icmp6.h

const (
	ICMP6_ECHO_REQUEST = 128
	ICMP6_ECHO_REPLY   = 129
)

func icmp6filter_set_blockall(filter *syscall.ICMPv6Filter) {
	for i := 0; i < len(filter.Data); i++ {
		filter.Data[i] = 0xff
	}
}

func icmp6filter_set_pass(filter *syscall.ICMPv6Filter, typ uint32) {
	filter.Data[typ>>5] &= ^(uint32(1) << (typ & 31))
}

func icmp6filter_setsockopt(fd int, filter *syscall.ICMPv6Filter) error {
	return syscall.SetsockoptICMPv6Filter(
		fd, syscall.IPPROTO_ICMPV6, syscall.ICMPV6_FILTER, filter)
}

func (server *Ping) sender6() {
	defer server.wg.Done()

	var buf [256]byte

	for seq := uint16(0); ; seq++ {
		n := (rand.Int() % 248) + 8

		log.Printf("ping seq %d, len %d", seq, n)
		buf[0] = ICMP6_ECHO_REQUEST // type
		buf[1] = 0		    // code
		buf[2] = 0		    // checksum[0]
		buf[3] = 0		    // checksum[1]
		if _, err := rand.Read(buf[8:n]); err != nil {
			log.Println(err)
			return
		}
		binary.BigEndian.PutUint16(buf[4:6], server.id)
		binary.BigEndian.PutUint16(buf[6:8], seq)

		if _, err := server.conn.Write(buf[:n]); err != nil {
			log.Println(err)
			return
		}
		time.Sleep(time.Duration(server.Internal * uint64(time.Second)))
	}
}

func (server *Ping) receiver6() {
	defer server.wg.Done()

	var buf [4096]byte

	for {
		n, err := server.conn.Read(buf[:])
		if err != nil {
			log.Println(err)
			return
		}
		if n < 8 {
			continue
		}

		typ := buf[0]
		code := buf[1]
		id := binary.BigEndian.Uint16(buf[4:6])
		seq := binary.BigEndian.Uint16(buf[6:8])
		if typ != ICMP6_ECHO_REPLY || code != 0 || id != server.id {
			continue
		}

		log.Printf("pong seq %d, len %d", seq, n)
	}
}

func (server *Ping) listenAndServer6() {
	conn, err := net.DialIP("ip6:ipv6-icmp", nil, server.addr)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()
	server.conn = conn

	f, err := conn.File()
	if err != nil {
		log.Println(err)
		return
	}
	filter := syscall.ICMPv6Filter{}
	icmp6filter_set_blockall(&filter)
	icmp6filter_set_pass(&filter, ICMP6_ECHO_REPLY)
	if err := icmp6filter_setsockopt(int(f.Fd()), &filter); err != nil {
		log.Println(err)
		return
	}

	server.wg.Add(2)
	go server.sender6()
	go server.receiver6()
	server.wg.Wait()
}
