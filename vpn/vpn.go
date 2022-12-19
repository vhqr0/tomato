package vpn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"log"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func timeStamp() uint64 {
	return uint64(time.Now().Unix())
}

func timeDelta(x, y uint64) uint64 {
	if x > y {
		return uint64(x - y)
	} else {
		return uint64(y - x)
	}
}

func hmacSum(msg []byte, key []byte) []byte {
	// crypto/hmac: why you have to append hamc to the end of msg?
	return hmac.New(md5.New, key).Sum(msg)[len(msg):]
}

const (
	devPath = "/dev/net/tun"
	ifrSize = unix.IFNAMSIZ + 64
)

type Vpn struct {
	LogTrace      bool
	DynUpdate     bool
	Iface         string
	LocalAddr     string
	PeerAddr      string
	LocalPwd      string
	PeerPwd       string
	PktValidTime  uint64
	AddrValidTime uint64

	wg        sync.WaitGroup
	tun       *os.File
	localConn *net.UDPConn
	peerAddr  *net.UDPAddr
	lastTs    uint64
	lastSeq   uint32
}

func (server *Vpn) waitingForPeer(now uint64) bool {
	return server.DynUpdate && timeDelta(now, server.lastTs) >= server.AddrValidTime
}

func (server *Vpn) shouldUpdatePeer(addr *net.UDPAddr) bool {
	return server.DynUpdate &&
		(!server.peerAddr.IP.Equal(addr.IP) ||
			server.peerAddr.Port != addr.Port)
}

func (server *Vpn) invalidPeer(addr *net.UDPAddr) bool {
	return !server.DynUpdate &&
		(!server.peerAddr.IP.Equal(addr.IP) ||
			server.peerAddr.Port != addr.Port)
}

func (server *Vpn) invalidHeader(now, ts uint64, seq uint32) bool {
	// notice: very rare case, seq inc from 0xffff to 0 in 1s will
	// cause packet loss, but don't fix it.
	return timeDelta(now, ts) >= server.PktValidTime ||
		ts < server.lastTs ||
		(ts == server.lastTs && seq <= server.lastSeq)
}

func (server *Vpn) sender() {
	defer server.wg.Done()

	var buf [4096]byte

	// get block cipher
	key := md5.Sum([]byte(server.LocalPwd))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		log.Println(err)
		return
	}

	for seq := uint32(0); ; seq++ {
		// get packet
		rn, err := server.tun.Read(buf[44:])
		if err != nil {
			log.Println(err)
			return
		}
		n := 44 + rn

		now := timeStamp()
		if server.waitingForPeer(now) {
			if server.LogTrace {
				log.Println("waiting for peer connection")
			}
			continue
		}

		// get plaintext
		binary.BigEndian.PutUint64(buf[32:40], now)
		binary.BigEndian.PutUint32(buf[40:44], seq)
		copy(buf[16:32], hmacSum(buf[32:n], key[:]))

		// get ciphertext
		if _, err := rand.Read(buf[:16]); err != nil {
			log.Println(err)
			return
		}
		stream := cipher.NewCTR(block, buf[:16])
		stream.XORKeyStream(buf[16:n], buf[16:n])

		// do send
		wn, err := server.localConn.WriteTo(buf[:n], server.peerAddr)
		if err != nil {
			log.Println(err)
			return
		}
		if wn != n {
			log.Println("write remote failed")
			return
		}

		if server.LogTrace {
			log.Printf("send %d bytes to %v", rn, server.peerAddr)
		}
	}
}

func (server *Vpn) receiver() {
	defer server.wg.Done()

	var buf [4096]byte

	// get block cipher
	key := md5.Sum([]byte(server.PeerPwd))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		log.Println(err)
		return
	}

	for {
		// get ciphertext
		rn, addr, err := server.localConn.ReadFromUDP(buf[:])
		if err != nil {
			log.Println(err)
			return
		}
		if rn < 44 {
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
				server.peerAddr, addr)
			server.peerAddr = addr
		}
		if rn == 44 {
			if server.LogTrace {
				log.Printf("recv 0 bytes from %v", addr)
			}
			continue
		}

		// do receive
		wn, err := server.tun.Write(buf[44:rn])
		if err != nil {
			log.Println(err)
			return
		}
		if wn+44 != rn {
			log.Println("write tun failed")
			return
		}
		if server.LogTrace {
			log.Printf("recv %d bytes from %v", wn, addr)
		}
	}
}

func (server *Vpn) ListenAndServe() {
	// open tun device
	fd, err := unix.Open(devPath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		log.Println(err)
		return
	}
	defer unix.Close(fd)

	// set tun interface
	var ifr [ifrSize]byte
	iface := []byte(server.Iface)
	if len(iface) >= unix.IFNAMSIZ {
		log.Println("interface overflow")
		return
	}
	copy(ifr[:], iface)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = unix.IFF_TUN
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		log.Println(errno.Error())
		return
	}

	// set nonblock
	if err := unix.SetNonblock(fd, true); err != nil {
		log.Println(err)
		return
	}

	// create tun
	tun := os.NewFile(uintptr(fd), devPath)
	defer tun.Close()
	server.tun = tun

	// resolve conn
	local, err := net.ResolveUDPAddr("udp", server.LocalAddr)
	if err != nil {
		log.Println(err)
		return
	}
	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()
	server.localConn = conn

	// resolve peer
	peer, err := net.ResolveUDPAddr("udp", server.PeerAddr)
	if err != nil {
		log.Println(err)
		return
	}
	server.peerAddr = peer

	// relay
	server.wg.Add(2)
	go server.sender()
	go server.receiver()
	server.wg.Wait()
}
