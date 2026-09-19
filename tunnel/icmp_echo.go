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
// unmapping IPv4-in-IPv6 forms so the socket lookup stays unambiguous. Both
// carrier shapes are accepted: a raw IPConn reports *net.IPAddr, and a ping
// socket — which the runtime classifies by its bound ident "port" — comes back
// as a UDPConn reporting *net.UDPAddr.
func netipAddrOf(a net.Addr) netip.Addr {
	var ip net.IP
	switch addr := a.(type) {
	case *net.IPAddr:
		if addr == nil {
			return netip.Addr{}
		}
		ip = addr.IP
	case *net.UDPAddr:
		if addr == nil {
			return netip.Addr{}
		}
		ip = addr.IP
	default:
		return netip.Addr{}
	}
	if ip == nil {
		return netip.Addr{}
	}
	if v4 := ip.To4(); v4 != nil {
		if addr, ok := netip.AddrFromSlice(v4); ok {
			return addr.Unmap()
		}
	}
	addr, ok := netip.AddrFromSlice(ip)
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
			return parseFragNeeded(msg)
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
			return parsePacketTooBig(msg)
		}
	}
	return inboundEcho{}, false
}

// parseFragNeeded decodes an IPv4 "fragmentation needed" report (RFC 1191).
// The next-hop MTU sits in the 16 bits at offset 6; a few implementations zero
// that and use offset 4 instead, so take whichever is populated.
//
// ICMP errors are unauthenticated, so this message is a forger's lever on our
// send budget unless the QUOTED original packet inside it is checked. RFC 792
// puts the original IP header (plus 64 bits of payload when it fits) in the
// message body; ours are recognisable, so require exactly that shape before
// reporting a budget at all:
//
//   - a full IPv4 header with no options (version 4, IHL 5 — we never emit
//     options), carrying protocol 1 (ICMP);
//   - the quoted datagram's first 8 bytes must be an ICMP echo header (type 0
//     or 8) — its sequence number is what the carrier cross-checks against
//     traffic it recently sent or received.
//
// A report that fails any of these is not ours (or not real) and is dropped;
// the in-band MTU search keeps working without it.
func parseFragNeeded(msg []byte) (inboundEcho, bool) {
	quoted, ok := quotedIPv4Echo(msg)
	if !ok {
		return inboundEcho{}, false
	}
	mtu := int(binary.BigEndian.Uint16(msg[6:8]))
	if mtu == 0 {
		mtu = int(binary.BigEndian.Uint16(msg[4:6]))
	}
	if mtu < 68 || mtu > 65535 {
		return inboundEcho{}, false
	}
	return inboundEcho{
		PathBudget: mtu - ipv4HeaderOverhead,
		QuotedSeq:  binary.BigEndian.Uint16(quoted[6:8]),
	}, true
}

// parsePacketTooBig is the IPv6 counterpart (RFC 4443 type 2): the MTU is the
// full 32 bits at offset 4, and the quoted original packet is an IPv6 header
// (always 40 bytes, no IHL subtleties) whose next-header field must be 58
// (ICMPv6) and whose first body bytes must look like our echo header. The same
// forgery logic as parseFragNeeded applies.
func parsePacketTooBig(msg []byte) (inboundEcho, bool) {
	const ipv6HeaderLen = 40
	if len(msg) < 8+ipv6HeaderLen {
		return inboundEcho{}, false
	}
	quotedIP := msg[8:]
	if quotedIP[0]>>4 != 6 {
		return inboundEcho{}, false
	}
	if quotedIP[6] != 58 { // next-header: ICMPv6
		return inboundEcho{}, false
	}
	if len(msg) < 8+ipv6HeaderLen+8 {
		return inboundEcho{}, false
	}
	quotedEcho := quotedIP[ipv6HeaderLen:][:8]
	if t := quotedEcho[0]; t != 0 && t != 128 && t != 129 {
		return inboundEcho{}, false
	}
	mtu := int(binary.BigEndian.Uint32(msg[4:8]))
	if mtu < 1280 || mtu > 1<<20 {
		return inboundEcho{}, false
	}
	return inboundEcho{
		PathBudget: mtu - ipv6HeaderOverhead,
		QuotedSeq:  binary.BigEndian.Uint16(quotedEcho[6:8]),
	}, true
}

// quotedIPv4Echo validates and returns the 8-byte quoted echo header inside a
// received IPv4 ICMP error: msg is the full ICMP error (header + payload), the
// quoted packet starts at offset 8, and it must be a 20-byte (no options)
// IPv4 header for protocol ICMP whose payload begins with an echo header.
func quotedIPv4Echo(msg []byte) ([]byte, bool) {
	const ipv4HeaderLen = 20
	if len(msg) < 8+ipv4HeaderLen {
		return nil, false
	}
	ip := msg[8:]
	if ip[0]>>4 != 4 { // version
		return nil, false
	}
	if ihl := int(ip[0]&0x0f) * 4; ihl != ipv4HeaderLen { // we never send options
		return nil, false
	}
	if ip[9] != 1 { // protocol: ICMP
		return nil, false
	}
	if len(msg) < 8+ipv4HeaderLen+8 {
		return nil, false
	}
	echo := ip[ipv4HeaderLen:][:8]
	if t := echo[0]; t != 0 && t != 8 { // the quoted datagram must be OUR echo
		return nil, false
	}
	return echo, true
}
