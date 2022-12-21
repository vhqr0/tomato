package vpn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"log"
	"net"
	"os"
)

type Vpn struct {
	LogTrace      bool
	DynUpdate     bool
	Iface         string
	LocalAddr     string
	LocalPwd      string
	PeerAddr      string
	PeerPwd       string
	PktValidTime  uint64
	AddrValidTime uint64

	tun     *os.File
	conn    *net.UDPConn
	peer    *net.UDPAddr
	lastTs  uint64
	lastSeq uint32
}

func (server *Vpn) sender() {
	var buf [4096]byte

	// get block cipher
	key := md5.Sum([]byte(server.LocalPwd))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		log.Fatal(err)
	}

	for seq := uint32(0); ; seq++ {
		// get packet
		rn, err := server.tun.Read(buf[44:])
		if err != nil {
			log.Fatal(err)
		}
		n := 44 + rn

		now := timeStamp()
		if server.waitingForPeer(now) {
			if server.LogTrace {
				log.Print("waiting for peer connection")
			}
			continue
		}

		// get plaintext
		binary.BigEndian.PutUint64(buf[32:40], now)
		binary.BigEndian.PutUint32(buf[40:44], seq)
		copy(buf[16:32], hmacSum(buf[32:n], key[:]))

		// get ciphertext
		if _, err := rand.Read(buf[:16]); err != nil {
			log.Fatal(err)
		}
		stream := cipher.NewCTR(block, buf[:16])
		stream.XORKeyStream(buf[16:n], buf[16:n])

		// do send
		if _, err := server.conn.WriteTo(buf[:n], server.peer); err != nil {
			log.Fatal(err)
		}

		if server.LogTrace {
			log.Printf("send %d bytes to %v", rn, server.peer)
		}
	}
}

func (server *Vpn) receiver() {
	var buf [4096]byte

	// get block cipher
	key := md5.Sum([]byte(server.PeerPwd))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		log.Fatal(err)
	}

	for {
		// get ciphertext
		rn, addr, err := server.conn.ReadFromUDP(buf[:])
		if err != nil {
			log.Fatal(err)
		}
		n := rn - 44

		if n < 0 {
			if server.LogTrace {
				log.Printf("invalid length from %v", addr)
			}
			continue
		}
		if server.invalidPeer(addr) {
			if server.LogTrace {
				log.Printf("invalid address from %v", addr)
			}
			continue
		}

		// get plaintext
		stream := cipher.NewCTR(block, buf[:16])
		stream.XORKeyStream(buf[16:rn], buf[16:rn])
		mac := hmacSum(buf[32:rn], key[:])
		if !bytes.Equal(mac, buf[16:32]) {
			if server.LogTrace {
				log.Printf("invalid hmac from %v", addr)
			}
			continue
		}

		// validate header
		ts := binary.BigEndian.Uint64(buf[32:40])
		seq := binary.BigEndian.Uint32(buf[40:44])
		if server.invalidHeader(timeStamp(), ts, seq) {
			if server.LogTrace {
				log.Printf("invalid header from %v", addr)
			}
			continue
		}

		// update state
		server.lastSeq = seq
		server.lastTs = ts
		if server.shouldUpdatePeer(addr) {
			log.Printf("update peer from %v to %v",
				server.peer, addr)
			server.peer = addr
		}
		if n == 0 {
			if server.LogTrace {
				log.Printf("recv 0 bytes from %v", addr)
			}
			continue
		}

		// do receive
		if _, err := server.tun.Write(buf[44:rn]); err != nil {
			log.Fatal(err)
		}
		if server.LogTrace {
			log.Printf("recv %d bytes from %v", n, addr)
		}
	}
}

func (server *Vpn) ListenAndServe() {
	if tun, err := openTun(server.Iface); err != nil {
		log.Fatal(err)
	} else {
		server.tun = tun
	}

	// resolve conn
	local, err := net.ResolveUDPAddr("udp", server.LocalAddr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		log.Fatal(err)
	}
	server.conn = conn

	// resolve peer
	peer, err := net.ResolveUDPAddr("udp", server.PeerAddr)
	if err != nil {
		log.Fatal(err)
	}
	server.peer = peer

	go server.receiver()
	server.sender()
}
