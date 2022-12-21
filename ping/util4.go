package ping

import "encoding/binary"

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

func getIcmpBuf(buf []byte) []byte {
	if len(buf) < 20 {
		return nil
	}
	hlen := int(buf[0]&0xf) << 2
	tlen := int(binary.BigEndian.Uint16(buf[2:4]))
	if tlen != len(buf) || tlen-hlen <= 8 {
		return nil
	}
	return buf[hlen:tlen]
}
