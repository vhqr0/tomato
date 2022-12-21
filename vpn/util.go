package vpn

import (
	"crypto/hmac"
	"crypto/md5"
	"net"
	"time"
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

func udpAddrEqual(a1 *net.UDPAddr, a2 *net.UDPAddr) bool {
	return a1.IP.Equal(a2.IP) && a1.Port == a2.Port
}

func (server *Vpn) waitingForPeer(now uint64) bool {
	return server.DynUpdate && timeDelta(now, server.lastTs) >= server.AddrValidTime
}

func (server *Vpn) shouldUpdatePeer(addr *net.UDPAddr) bool {
	return server.DynUpdate && !udpAddrEqual(addr, server.peer)
}

func (server *Vpn) invalidPeer(addr *net.UDPAddr) bool {
	return !server.DynUpdate && !udpAddrEqual(addr, server.peer)
}

func (server *Vpn) invalidHeader(now, ts uint64, seq uint32) bool {
	// notice: very rare case, seq inc from 0xffff to 0 in 1s will
	// cause packet loss, but don't fix it.
	return timeDelta(now, ts) >= server.PktValidTime ||
		ts < server.lastTs ||
		(ts == server.lastTs && seq <= server.lastSeq)
}
