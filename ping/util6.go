package ping

import (
	"net"
	"syscall"
)

const (
	ICMP6_ECHO_REQUEST = 128
	ICMP6_ECHO_REPLY   = 129
)

// see /usr/include/netinet/icmp6.h

type icmp6Filter syscall.ICMPv6Filter

func (filter *icmp6Filter) setBlockAll() {
	for i := 0; i < len(filter.Data); i++ {
		filter.Data[i] = 0xff
	}
}

func (filter *icmp6Filter) setPass(typ uint32) {
	filter.Data[typ>>5] &= ^(uint32(1) << (typ & 31))
}

func (filter *icmp6Filter) setSockOpt(fd int) error {
	return syscall.SetsockoptICMPv6Filter(
		fd, syscall.IPPROTO_ICMPV6, syscall.ICMPV6_FILTER,
		(*syscall.ICMPv6Filter)(filter))
}

func (filter *icmp6Filter) setConnOpt(conn *net.IPConn) error {
	if f, err := conn.File(); err != nil {
		return err
	} else {
		return filter.setSockOpt(int(f.Fd()))
	}
}
