package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Shared ICMP Echo plumbing.
//
// Everything here is pure Go — no sockets, no syscall constants — so every
// platform file (raw Linux, Android ping sockets) composes the same building
// blocks instead of growing its own diverging copy. The platform files agree
// only on the newPlatformICMPTransport signature; the WIRE format they put on
// the air is defined here, once.

const (
	// ipv4HeaderOverhead is the fixed IPv4 header plus the ICMP header: what a
	// frag-needed report's "next hop MTU" includes beyond our payload.
	ipv4HeaderOverhead = 20 + 8
	// ipv6HeaderOverhead is the fixed IPv6 header plus the ICMPv6 header.
	ipv6HeaderOverhead = 40 + 8
)

// combineOpenErrors turns a list of socket failures into one error that keeps
// every actionable sentinel in its chain: with family "auto" an operator needs
// to see that the IPv6 half failed for a different reason than the IPv4 half.
func combineOpenErrors(errs []error) error {
	if len(errs) == 0 {
		return fmt.Errorf("%w: no ICMP socket could be opened", ErrTransportUnsupported)
	}
	if len(errs) == 1 {
		return errs[0]
	}
	return errors.Join(errs...)
}

// netipAddrOf converts a net.Addr reported by a socket read into a netip.Addr,
// unmapping IPv4-in-IPv6 forms so the socket lookup stays unambiguous.
func netipAddrOf(a net.Addr) netip.Addr {
	ipa, ok := a.(*net.IPAddr)
	if !ok || ipa.IP == nil {
		return netip.Addr{}
	}
	if v4 := ipa.IP.To4(); v4 != nil {
		if addr, ok := netip.AddrFromSlice(v4); ok {
			return addr.Unmap()
		}
	}
	addr, ok := netip.AddrFromSlice(ipa.IP)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// buildEchoMessage lays out an ICMP/ICMPv6 Echo message. withChecksum is true
// only for a raw IPv4 socket: RFC 3542 §3.1 has the kernel compute and insert
// the ICMPv6 checksum (and setting IPV6_CHECKSUM on an ICMPv6 socket is
// rejected EINVAL), and a ping socket's kernel builds the whole IP header and
// checksum for both families.
func buildEchoMessage(msgType byte, ident, seq uint16, payload []byte, withChecksum bool) []byte {
	msg := make([]byte, 8+len(payload))
	msg[0] = msgType
	msg[1] = 0
	// msg[2:4] stays zero whenever the kernel writes the checksum.
	binary.BigEndian.PutUint16(msg[4:6], ident)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	copy(msg[8:], payload)
	if withChecksum {
		binary.BigEndian.PutUint16(msg[2:4], icmpv4Checksum(msg))
	}
	return msg
}

// icmpv4Checksum is the RFC 1071 one's-complement sum over the ICMP message
// only — ICMPv4's checksum deliberately excludes the IPv4 pseudo-header.
func icmpv4Checksum(msg []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(msg); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(msg[i : i+2]))
	}
	if len(msg)%2 == 1 {
		sum += uint32(msg[len(msg)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// parseICMPMessage decodes a bare ICMP/ICMPv6 message (no IP header) into an
// inboundEcho. It reports false for anything that is neither an Echo we can
// use nor a path-MTU report. A ping socket hands over exactly this shape; a
// raw IPv4 socket delivers the IPv4 header first and the platform strips it
// before calling in.
func parseICMPMessage(msg []byte, family int) (inboundEcho, bool) {
	if len(msg) < 8 {
		return inboundEcho{}, false
	}
	switch family {
	case 4:
		switch msg[0] {
		case 0, 8: // echo reply, echo request
			return inboundEcho{
				Payload:   msg[8:],
				Path:      PathID{Ident: binary.BigEndian.Uint16(msg[4:6]), Seq: binary.BigEndian.Uint16(msg[6:8])},
				IsRequest: msg[0] == 8,
			}, true
		case 3:
			if msg[1] != 4 { // only "fragmentation needed"
				return inboundEcho{}, false
			}
			// RFC 1191 puts the next-hop MTU in the 16 bits at offset 6. A few
			// implementations zero that and use offset 4 instead, so take
			// whichever is populated.
			mtu := int(binary.BigEndian.Uint16(msg[6:8]))
			if mtu == 0 {
				mtu = int(binary.BigEndian.Uint16(msg[4:6]))
			}
			if mtu < 68 || mtu > 65535 {
				return inboundEcho{}, false
			}
			return inboundEcho{PathBudget: mtu - ipv4HeaderOverhead}, true
		}
	case 6:
		switch msg[0] {
		case 129, 128: // echo reply, echo request
			return inboundEcho{
				Payload:   msg[8:],
				Path:      PathID{Ident: binary.BigEndian.Uint16(msg[4:6]), Seq: binary.BigEndian.Uint16(msg[6:8])},
				IsRequest: msg[0] == 128,
			}, true
		case 2: // Packet Too Big
			mtu := int(binary.BigEndian.Uint32(msg[4:8]))
			if mtu < 1280 || mtu > 1<<20 {
				return inboundEcho{}, false
			}
			return inboundEcho{PathBudget: mtu - ipv6HeaderOverhead}, true
		}
	}
	return inboundEcho{}, false
}
