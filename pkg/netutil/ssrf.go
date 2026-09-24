package netutil

import (
	"fmt"
	"net/netip"
	"slices"
)

// Block reasons. Stable strings — emitted in audit events and error
// messages, change them only with a coordinated update of the audit
// catalogue.
const (
	BlockReasonLoopback      = "loopback"
	BlockReasonUnspecified   = "unspecified"
	BlockReasonLinkLocal     = "link_local"
	BlockReasonPrivate       = "private"
	BlockReasonMulticast     = "multicast"
	BlockReasonCloudMetadata = "cloud_metadata"
	BlockReasonCGNAT         = "cgnat"
	BlockReasonReservedV4    = "reserved_v4"
)

// IPv6 ranges that carry an IPv4 destination inside the address. A dial to
// one of them is delivered to, or tunnelled through, the embedded IPv4 host
// (a NAT64 or SIIT translator, a 6to4 relay, a Teredo peer or an automatic
// tunnel), so the blocklist has to judge that host.
var (
	// RFC 6052 well-known NAT64 prefix, IPv4 in the low 32 bits.
	nat64WellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")
	// RFC 3056 6to4, IPv4 in bits 16-47.
	sixToFourPrefix = netip.MustParsePrefix("2002::/16")
	// RFC 4380 Teredo, the client's IPv4 inverted in the low 32 bits.
	teredoPrefix = netip.MustParsePrefix("2001::/32")
	// RFC 2765 SIIT IPv4-translated addresses, IPv4 in the low 32 bits.
	ipv4TranslatedPrefix = netip.MustParsePrefix("::ffff:0:0:0/96")
	// RFC 4291 IPv4-compatible addresses (deprecated), IPv4 in the low 32 bits.
	ipv4CompatiblePrefix = netip.MustParsePrefix("::/96")
	// RFC 8215 local-use NAT64 prefix. The operator picks the prefix length,
	// so outside the /96 below the embedded IPv4 cannot be located and the
	// range is private.
	nat64LocalUsePrefix = netip.MustParsePrefix("64:ff9b:1::/48")
	// The /96 layout of the local-use prefix, IPv4 in the low 32 bits. Read
	// with the /48, /56 or /64 layout these addresses decode into 0.0.0.0/8,
	// which no translator delivers, so the low 32 bits are the destination.
	nat64LocalUse96Prefix = netip.MustParsePrefix("64:ff9b:1::/96")
)

// cloudMetadataAddrs are the instance metadata and credential endpoints that
// DialBlockReason refuses whatever the operator relaxed.
var cloudMetadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),    // AWS, GCP, Azure, DigitalOcean, Oracle, OpenStack
	netip.MustParseAddr("fd00:ec2::254"),      // AWS over IPv6
	netip.MustParseAddr("169.254.170.2"),      // AWS ECS task credentials
	netip.MustParseAddr("169.254.170.23"),     // AWS EKS Pod Identity
	netip.MustParseAddr("fd00:ec2::23"),       // AWS EKS Pod Identity over IPv6
	netip.MustParseAddr("fd20:ce::254"),       // GCP on IPv6-only VMs
	netip.MustParseAddr("fd00:c1::a9fe:a9fe"), // Oracle Cloud over IPv6
	netip.MustParseAddr("fe80::a9fe:a9fe"),    // OpenStack over IPv6
	netip.MustParseAddr("168.63.129.16"),      // Azure WireServer
	netip.MustParseAddr("100.100.100.200"),    // Alibaba Cloud
	netip.MustParseAddr("169.254.0.23"),       // Tencent Cloud
	netip.MustParseAddr("169.254.42.42"),      // Scaleway
	netip.MustParseAddr("fd00:42::42"),        // Scaleway over IPv6
}

// IsBlockedIP reports whether BlockReason finds a reason to refuse ip: every
// address that could route to a panel-local service, a hypervisor metadata
// endpoint, an internal corporate network or a multicast scope is blocked.
// It classifies only; what an operator may relax, and that cloud metadata
// never is, is decided by DialBlockReason.
//
// The function works on netip.Addr (Go's modern, value-typed IP) so
// callers can pass results from net.Resolver.LookupNetIP directly
// without conversions.
func IsBlockedIP(ip netip.Addr) bool {
	return BlockReason(ip) != ""
}

// IsCloudMetadataIP returns true for the cloud-provider metadata and
// credential endpoints in cloudMetadataAddrs. Most of them are link-local
// or ULA and the blocklist covers them anyway, but the dedicated check lets
// DialBlockReason refuse them even where the operator relaxed the rest.
//
// The IPv4-mapped, NAT64, 6to4, Teredo, SIIT, IPv4-compatible and zoned
// spellings of an endpoint match too (see effectiveAddr), and inside the
// local-use NAT64 prefix every RFC 6052 layout is tried.
func IsCloudMetadataIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	return isCloudMetadata(effectiveAddr(ip))
}

// isCloudMetadata is IsCloudMetadataIP for an address effectiveAddr already
// reduced.
func isCloudMetadata(ip netip.Addr) bool {
	if slices.Contains(cloudMetadataAddrs, ip) {
		return true
	}

	if !nat64LocalUsePrefix.Contains(ip) {
		return false
	}

	a16 := ip.As16()

	// RFC 6052 layouts that fit in the /48; octet 8 is reserved and skipped.
	for _, v4 := range [][4]byte{
		{a16[6], a16[7], a16[9], a16[10]},    // /48
		{a16[7], a16[9], a16[10], a16[11]},   // /56
		{a16[9], a16[10], a16[11], a16[12]},  // /64
		{a16[12], a16[13], a16[14], a16[15]}, // /96
	} {
		if slices.Contains(cloudMetadataAddrs, netip.AddrFrom4(v4)) {
			return true
		}
	}

	return false
}

// BlockReason returns a stable, audit-friendly identifier for why an IP is
// blocked, or "" if the IP is acceptable. Categories are checked in a
// fixed order so an IP that matches multiple categories (e.g. a cloud
// metadata address which is also link-local) reports the most-specific
// reason first.
//
// The address is judged by where a dial to it lands (see effectiveAddr), so
// ::ffff:127.0.0.1, 64:ff9b::7f00:1 and 2002:7f00:1:: all report loopback.
//
// Order:
//
//  1. cloud_metadata (most specific — DialBlockReason never relaxes it)
//  2. loopback
//  3. unspecified (0.0.0.0, ::)
//  4. link_local (RFC 3927 / RFC 4291)
//  5. multicast
//  6. private (RFC 1918 / RFC 4193 ULA / RFC 8215 local-use NAT64)
//  7. cgnat (RFC 6598 100.64.0.0/10)
//  8. reserved_v4 (0.0.0.0/8 source-only, 240.0.0.0/4 future, broadcast)
func BlockReason(ip netip.Addr) string {
	if !ip.IsValid() {
		return BlockReasonReservedV4
	}

	ip = effectiveAddr(ip)

	if isCloudMetadata(ip) {
		return BlockReasonCloudMetadata
	}

	if ip.IsLoopback() {
		return BlockReasonLoopback
	}

	if ip.IsUnspecified() {
		return BlockReasonUnspecified
	}

	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return BlockReasonLinkLocal
	}

	if ip.IsMulticast() {
		return BlockReasonMulticast
	}

	if ip.IsPrivate() || nat64LocalUsePrefix.Contains(ip) {
		return BlockReasonPrivate
	}

	if isCGNAT(ip) {
		return BlockReasonCGNAT
	}

	if isReservedV4(ip) {
		return BlockReasonReservedV4
	}

	return ""
}

// DialBlockReason applies the plugin egress policy to one resolved address
// and returns why the dial must be refused, or "" if it may proceed. Cloud
// metadata is refused whatever the operator relaxed; everything else only
// while blockPrivate is on and the host is not on the operator allow-list.
//
// The dials the plugin host libraries make for a plugin (gameap-http,
// gameap-ssh, plugin game protocols) judge every resolved address through
// this one function, so a hardening step cannot land in one of them and miss
// the others. An invalid address is refused whatever the policy.
func DialBlockReason(ip netip.Addr, blockPrivate, allowlisted bool) string {
	if !ip.IsValid() {
		return BlockReasonReservedV4
	}

	if IsCloudMetadataIP(ip) {
		return BlockReasonCloudMetadata
	}

	if !blockPrivate || allowlisted {
		return ""
	}

	return BlockReason(ip)
}

// BlockedDialDetail describes a refused dial for errors and audit events as
// "ip=<judged address> reason=<reason>", adding "requested=<address>" when
// the dial named it in another form, so a search for one address finds every
// spelling of it.
func BlockedDialDetail(ip netip.Addr, reason string) string {
	effective := effectiveAddr(ip)
	if effective == ip {
		return fmt.Sprintf("ip=%s reason=%s", ip, reason)
	}

	return fmt.Sprintf("ip=%s reason=%s requested=%s", effective, reason, ip)
}

// effectiveAddr returns the address the blocklist judges for ip: the host a
// dial to it is delivered to or tunnelled through. The zone is dropped (it
// only picks an interface), IPv4-mapped addresses are unwrapped (Go dials
// them as plain IPv4), and the IPv4 embedded by NAT64, 6to4, Teredo, SIIT or
// the IPv4-compatible format is extracted. The result is for classification
// only: callers keep dialing the original address, so NAT64 still works on
// IPv6-only hosts.
func effectiveAddr(ip netip.Addr) netip.Addr {
	ip = ip.WithZone("").Unmap()
	if !ip.Is6() {
		return ip
	}

	a16 := ip.As16()

	switch {
	case nat64WellKnownPrefix.Contains(ip), nat64LocalUse96Prefix.Contains(ip), ipv4TranslatedPrefix.Contains(ip):
		return netip.AddrFrom4([4]byte(a16[12:16]))
	case sixToFourPrefix.Contains(ip):
		return netip.AddrFrom4([4]byte(a16[2:6]))
	case teredoPrefix.Contains(ip):
		return netip.AddrFrom4([4]byte{^a16[12], ^a16[13], ^a16[14], ^a16[15]})
	case ipv4CompatiblePrefix.Contains(ip) && !ip.IsLoopback() && !ip.IsUnspecified():
		// :: and ::1 sit in ::/96 as well but keep their IPv6 meaning.
		return netip.AddrFrom4([4]byte(a16[12:16]))
	}

	return ip
}

// isCGNAT covers RFC 6598 100.64.0.0/10. Go's netip.Addr.IsPrivate does
// NOT include this range (RFC 1918 only), but a panel deployed inside a
// carrier-grade NAT segment can still reach neighbour customer subnets,
// so we block it.
func isCGNAT(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}

	a4 := ip.As4()
	// 100.64.0.0/10 -> first octet 100, second 64..127.
	return a4[0] == 100 && a4[1] >= 64 && a4[1] <= 127
}

// isReservedV4 covers the IPv4 reserved ranges that don't fall under
// loopback/unspecified/link-local/multicast/private but should still
// never appear in an outbound request: the 0.0.0.0/8 source-only range
// (RFC 6890) and the 240.0.0.0/4 future-use range (RFC 1112) including
// the all-ones broadcast 255.255.255.255.
func isReservedV4(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}

	a4 := ip.As4()

	// 0.0.0.0/8 (the 0.0.0.0 = unspecified case is already handled above,
	// but 0.x.x.x for any x is still "this network" and not routable).
	if a4[0] == 0 {
		return true
	}

	// 240.0.0.0/4 (future use) — covers 255.255.255.255 too.
	if a4[0] >= 240 {
		return true
	}

	return false
}
