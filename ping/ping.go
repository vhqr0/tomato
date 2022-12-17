package tomato

import (
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"
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

type Ping struct {
	PeerAddr string
	Internal uint64

	wg   sync.WaitGroup
	conn net.Conn
	id   uint16
}

func (ping *Ping) sender() {
	defer ping.wg.Done()

	var buf [256]byte

	for seq := uint16(0); ; seq++ {
		n := (rand.Int() & 248) + 8

		log.Printf("ping seq %d, len %d", seq, n)

		buf[0] = 8 // type:echo
		buf[1] = 0 // code
		buf[2] = 0 // checksum[0]
		buf[3] = 0 // checksum[1]
		if _, err := rand.Read(buf[8:n]); err != nil {
			log.Println(err)
			return
		}
		binary.BigEndian.PutUint16(buf[4:6], ping.id)
		binary.BigEndian.PutUint16(buf[6:8], seq)
		binary.BigEndian.PutUint16(buf[2:4], checkSum(buf[:n]))

		if _, err := ping.conn.Write(buf[:n]); err != nil {
			log.Println(err)
			return
		}
		time.Sleep(time.Duration(ping.Internal * uint64(time.Second)))
	}
}

func (ping *Ping) receiver() {
	defer ping.wg.Done()

	var buf [4096]byte

	for {
		n, err := ping.conn.Read(buf[:])
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
		if typ != 0 || code != 0 || id != ping.id {
			continue
		}

		log.Printf("pong seq %d, len %d", seq, len(icmpbuf))
	}
}

func (ping *Ping) ListenAndServe() {
	ping.id = uint16(os.Getpid())

	conn, err := net.Dial("ip4:icmp", ping.PeerAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()
	ping.conn = conn

	ping.wg.Add(2)
	go ping.sender()
	go ping.receiver()
	ping.wg.Wait()
}
