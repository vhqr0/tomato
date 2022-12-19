package ping

import (
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"time"
)

const (
	ICMP_ECHO_REPLY   = 0
	ICMP_ECHO_REQUEST = 8
)

func checkSum(msg []byte) uint16 {
	sum := uint32(0)
	var i int
	for i = 0; i < len(msg)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(msg[i : i+2]))
	}
	if i == len(msg)-1 { // odd
		sum += uint32(uint16(msg[i]) << 8)
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	return ^uint16(sum)
}

func (server *Ping) sender4() {
	defer server.wg.Done()

	var buf [256]byte

	for seq := uint16(0); ; seq++ {
		n := (rand.Int() % 248) + 8

		log.Printf("ping seq %d, len %d", seq, n)

		buf[0] = ICMP_ECHO_REQUEST // type
		buf[1] = 0                 // code
		buf[2] = 0                 // checksum[0]
		buf[3] = 0                 // checksum[1]
		if _, err := rand.Read(buf[8:n]); err != nil {
			log.Println(err)
			return
		}
		binary.BigEndian.PutUint16(buf[4:6], server.id)
		binary.BigEndian.PutUint16(buf[6:8], seq)
		binary.BigEndian.PutUint16(buf[2:4], checkSum(buf[:n]))

		if _, err := server.conn.Write(buf[:n]); err != nil {
			log.Println(err)
			return
		}
		time.Sleep(time.Duration(server.Internal * uint64(time.Second)))
	}
}

func (server *Ping) receiver4() {
	defer server.wg.Done()

	var buf [4096]byte

	for {
		n, err := server.conn.Read(buf[:])
		if err != nil {
			log.Println(err)
			return
		}
		if n < 20 {
			continue
		}
		hlen := int(buf[0]&0xf) << 2
		tlen := int(binary.BigEndian.Uint16(buf[2:4]))
		if tlen != n || tlen-hlen <= 8 {
			continue
		}
		icmpbuf := buf[hlen:tlen]

		typ := icmpbuf[0]
		code := icmpbuf[1]
		id := binary.BigEndian.Uint16(icmpbuf[4:6])
		seq := binary.BigEndian.Uint16(icmpbuf[6:8])
		if typ != ICMP_ECHO_REPLY || code != 0 || id != server.id {
			continue
		}

		log.Printf("pong seq %d, len %d", seq, len(icmpbuf))
	}
}

func (server *Ping) listenAndServe4() {
	conn, err := net.DialIP("ip4:icmp", nil, server.addr)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()
	server.conn = conn

	server.wg.Add(2)
	go server.sender4()
	go server.receiver4()
	server.wg.Wait()
}
