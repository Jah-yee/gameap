// API Security Tests for OWASP API Security Top 10:2023.
// Category: API7:2023 — Server-Side Request Forgery.
//
// Pins the SSRF blocklist used by the plugin HTTP host library. A
// regression here would re-open the loopback / RFC1918 / cloud-metadata
// pivot from a compromised plugin into the panel's host network.
//
// Reference: https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/
package netutil_test

import (
	"net/netip"
	"testing"

	"github.com/gameap/gameap/pkg/netutil"
	"github.com/stretchr/testify/assert"
)

func TestIsBlockedIP_BlocksLoopback(t *testing.T) {
	t.Parallel()

	cases := []string{
		"127.0.0.1",
		"127.255.255.254",
		"::1",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(raw)
			assert.True(t, netutil.IsBlockedIP(ip))
			assert.Equal(t, netutil.BlockReasonLoopback, netutil.BlockReason(ip))
		})
	}
}

func TestIsBlockedIP_BlocksPrivateRFC1918(t *testing.T) {
	t.Parallel()

	cases := []string{
		"10.0.0.1",
		"10.255.255.254",
		"172.16.0.1",
		"172.31.255.254",
		"192.168.0.1",
		"192.168.255.254",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(raw)
			assert.True(t, netutil.IsBlockedIP(ip))
			assert.Equal(t, netutil.BlockReasonPrivate, netutil.BlockReason(ip))
		})
	}
}

func TestIsBlockedIP_BlocksIPv6ULA(t *testing.T) {
	t.Parallel()

	cases := []string{
		"fc00::1",
		"fd00::1",
		"fdff:ffff:ffff:ffff::1",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(raw)
			assert.True(t, netutil.IsBlockedIP(ip))
			assert.Equal(t, netutil.BlockReasonPrivate, netutil.BlockReason(ip))
		})
	}
}

func TestIsBlockedIP_BlocksLinkLocal(t *testing.T) {
	t.Parallel()

	cases := []string{
		"169.254.1.1", // not the metadata IP
		"169.254.255.254",
		"fe80::1",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(raw)
			assert.True(t, netutil.IsBlockedIP(ip))
			assert.Equal(t, netutil.BlockReasonLinkLocal, netutil.BlockReason(ip))
		})
	}
}

func TestIsBlockedIP_BlocksCloudMetadata(t *testing.T) {
	t.Parallel()

	cases := []string{
		"169.254.169.254",
		"fd00:ec2::254",
		"100.100.100.200",
		"169.254.170.2",      // AWS ECS task credentials
		"169.254.170.23",     // AWS EKS Pod Identity
		"fd00:ec2::23",       // AWS EKS Pod Identity over IPv6
		"fd20:ce::254",       // GCP on IPv6-only VMs
		"fd00:c1::a9fe:a9fe", // Oracle Cloud over IPv6
		"fe80::a9fe:a9fe",    // OpenStack over IPv6
		"168.63.129.16",      // Azure WireServer, a public address
		"169.254.0.23",       // Tencent Cloud
		"169.254.42.42",      // Scaleway
		"fd00:42::42",        // Scaleway over IPv6
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(raw)
			assert.True(t, netutil.IsBlockedIP(ip))
			assert.True(t, netutil.IsCloudMetadataIP(ip))
			assert.Equal(t, netutil.BlockReasonCloudMetadata, netutil.BlockReason(ip),
				"cloud-metadata reason must be reported BEFORE the broader link-local reason")
		})
	}
}

func TestIsBlockedIP_BlocksUnspecified(t *testing.T) {
	t.Parallel()

	cases := []string{"0.0.0.0", "::"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(raw)
			assert.True(t, netutil.IsBlockedIP(ip))
			// 0.0.0.0 hits both "unspecified" and "reserved_v4 (0.0.0.0/8)";
			// our ordering reports unspecified first because it's the
			// more specific operator-visible signal.
			assert.Equal(t, netutil.BlockReasonUnspecified, netutil.BlockReason(ip))
		})
	}
}

func TestIsBlockedIP_BlocksMulticast(t *testing.T) {
	t.Parallel()

	cases := []string{
		"224.0.0.1",
		"239.255.255.250", // SSDP
		"ff02::1",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(raw)
			assert.True(t, netutil.IsBlockedIP(ip))
			reason := netutil.BlockReason(ip)
			// IPv6 multicast (ff02::) is also link-local-scoped, which
			// matches earlier in the order; either reason is acceptable.
			assert.Contains(t, []string{netutil.BlockReasonMulticast, netutil.BlockReasonLinkLocal}, reason,
				"got %q", reason)
		})
	}
}

func TestIsBlockedIP_BlocksCGNAT(t *testing.T) {
	t.Parallel()

	cases := []string{
		"100.64.0.1",
		"100.127.255.254",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(raw)
			assert.True(t, netutil.IsBlockedIP(ip))
			assert.Equal(t, netutil.BlockReasonCGNAT, netutil.BlockReason(ip))
		})
	}
}

func TestIsBlockedIP_BlocksReservedV4(t *testing.T) {
	t.Parallel()

	cases := []string{
		"0.1.2.3",   // 0.0.0.0/8 — "this network"
		"240.0.0.1", // 240.0.0.0/4 — future use
		"255.255.255.255",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(raw)
			assert.True(t, netutil.IsBlockedIP(ip))
			assert.Equal(t, netutil.BlockReasonReservedV4, netutil.BlockReason(ip))
		})
	}
}

func TestIsBlockedIP_AllowsPublicAddresses(t *testing.T) {
	t.Parallel()

	cases := []string{
		"8.8.8.8",
		"1.1.1.1",
		"99.99.99.99",
		"203.0.113.42", // TEST-NET-3 — not private, technically routable
		"2001:db8::1",  // documentation prefix — not private/ULA/link-local
		"2606:4700:4700::1111",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(raw)
			assert.False(t, netutil.IsBlockedIP(ip), "public IP must be allowed")
			assert.Empty(t, netutil.BlockReason(ip))
		})
	}
}

func TestIsCloudMetadataIP_RejectsLookalikes(t *testing.T) {
	t.Parallel()

	// IPs that are link-local but NOT the metadata endpoint must NOT
	// match IsCloudMetadataIP — otherwise an allow-list bypass that
	// trusts "not metadata" would accidentally allow IMDS access.
	cases := []string{
		"169.254.169.253",
		"169.254.169.255",
		"169.254.1.1",
		"100.100.100.199",
		"100.100.100.201",
		"64:ff9b::a9fe:a9fd", // NAT64 spelling of 169.254.169.253
		"::ffff:169.254.169.253",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(raw)
			assert.False(t, netutil.IsCloudMetadataIP(ip))
		})
	}
}

func TestBlockReason_InvalidAddrIsRejected(t *testing.T) {
	t.Parallel()

	// netip.Addr zero value (Addr{}) is !IsValid() — must be rejected.
	var zero netip.Addr
	assert.True(t, netutil.IsBlockedIP(zero))
	assert.Equal(t, netutil.BlockReasonReservedV4, netutil.BlockReason(zero))

	// The dial policy must not approve it either, whatever was relaxed.
	for _, relaxed := range []struct{ blockPrivate, allowlisted bool }{
		{true, false}, {false, false}, {true, true},
	} {
		assert.Equal(t, netutil.BlockReasonReservedV4,
			netutil.DialBlockReason(zero, relaxed.blockPrivate, relaxed.allowlisted), "%+v", relaxed)
	}
}

// An IPv4 destination must be judged the same whatever IPv6 form it is
// written in: Go dials IPv4-mapped addresses as plain IPv4, and NAT64, 6to4,
// Teredo, SIIT and IPv4-compatible addresses land on the embedded IPv4 host.
// A zone only picks an interface and must not hide the address either.
func TestBlockReason_JudgesEmbeddedIPv4(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
		want string
	}{
		{"mapped_aws_metadata", "::ffff:169.254.169.254", netutil.BlockReasonCloudMetadata},
		{"mapped_alibaba_metadata", "::ffff:100.100.100.200", netutil.BlockReasonCloudMetadata},
		{"nat64_aws_metadata", "64:ff9b::a9fe:a9fe", netutil.BlockReasonCloudMetadata},
		{"nat64_alibaba_metadata", "64:ff9b::6464:64c8", netutil.BlockReasonCloudMetadata},
		{"6to4_aws_metadata", "2002:a9fe:a9fe::", netutil.BlockReasonCloudMetadata},
		{"ipv4_compatible_aws_metadata", "::a9fe:a9fe", netutil.BlockReasonCloudMetadata},
		{"zoned_aws_ipv6_metadata", "fd00:ec2::254%eth0", netutil.BlockReasonCloudMetadata},
		{"mapped_unspecified", "::ffff:0.0.0.0", netutil.BlockReasonUnspecified},
		{"mapped_loopback", "::ffff:127.0.0.1", netutil.BlockReasonLoopback},
		{"mapped_cgnat", "::ffff:100.64.0.1", netutil.BlockReasonCGNAT},
		{"mapped_reserved", "::ffff:240.0.0.1", netutil.BlockReasonReservedV4},
		{"nat64_loopback", "64:ff9b::7f00:1", netutil.BlockReasonLoopback},
		{"nat64_private", "64:ff9b::a00:1", netutil.BlockReasonPrivate},
		{"nat64_link_local", "64:ff9b::a9fe:101", netutil.BlockReasonLinkLocal},
		{"6to4_private", "2002:a00:1::", netutil.BlockReasonPrivate},
		{"6to4_unspecified", "2002::", netutil.BlockReasonUnspecified},
		{"ipv4_compatible_private", "::a00:1", netutil.BlockReasonPrivate},
		{"nat64_local_use_prefix", "64:ff9b:1::a00:1", netutil.BlockReasonPrivate},
		{"nat64_local_use_loopback", "64:ff9b:1::7f00:1", netutil.BlockReasonLoopback},
		{"nat64_local_use_aws_metadata", "64:ff9b:1::a9fe:a9fe", netutil.BlockReasonCloudMetadata},
		// Outside 64:ff9b:1::/96 the operator's layout is unknown, so the
		// metadata check tries each RFC 6052 layout and the rest is private.
		{"nat64_local_use_48_aws_metadata", "64:ff9b:1:a9fe:a9:fe00::", netutil.BlockReasonCloudMetadata},
		{"nat64_local_use_56_aws_metadata", "64:ff9b:1:a9:fe:a9fe::", netutil.BlockReasonCloudMetadata},
		{"nat64_local_use_64_aws_metadata", "64:ff9b:1:0:a9:fea9:fe00:0", netutil.BlockReasonCloudMetadata},
		{"nat64_local_use_other_96_aws_metadata", "64:ff9b:1:abcd::a9fe:a9fe", netutil.BlockReasonCloudMetadata},
		{"nat64_local_use_other_layout", "64:ff9b:1:abcd::808:808", netutil.BlockReasonPrivate},
		// Teredo stores the client's IPv4 inverted in the low 32 bits.
		{"teredo_aws_metadata", "2001:0:4136:e378:8000:63bf:5601:5601", netutil.BlockReasonCloudMetadata},
		{"teredo_loopback", "2001:0:4136:e378:8000:63bf:80ff:fffe", netutil.BlockReasonLoopback},
		{"teredo_private", "2001:0:4136:e378:8000:63bf:f5ff:fffe", netutil.BlockReasonPrivate},
		{"siit_aws_metadata", "::ffff:0:a9fe:a9fe", netutil.BlockReasonCloudMetadata},
		{"siit_loopback", "::ffff:0:7f00:1", netutil.BlockReasonLoopback},
		{"zoned_openstack_metadata", "fe80::a9fe:a9fe%eth0", netutil.BlockReasonCloudMetadata},
		{"zoned_link_local", "fe80::1%eth0", netutil.BlockReasonLinkLocal},
		// :: and ::1 sit inside the IPv4-compatible range but keep their
		// IPv6 meaning, so the audited reason does not change.
		{"ipv6_loopback_keeps_reason", "::1", netutil.BlockReasonLoopback},
		{"ipv6_unspecified_keeps_reason", "::", netutil.BlockReasonUnspecified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(tt.addr)
			assert.Equal(t, tt.want, netutil.BlockReason(ip))
			assert.True(t, netutil.IsBlockedIP(ip))
			assert.Equal(t, tt.want == netutil.BlockReasonCloudMetadata, netutil.IsCloudMetadataIP(ip))
		})
	}
}

// Normalisation must not over-block: a public IPv4 host stays reachable in
// any spelling. NAT64 in particular is how IPv6-only (DNS64) hosts reach
// every IPv4-only service.
func TestBlockReason_AllowsEmbeddedPublicIPv4(t *testing.T) {
	t.Parallel()

	cases := []string{
		"::ffff:8.8.8.8",
		"64:ff9b::808:808",
		"64:ff9b:1::808:808", // DNS64 synthesising into the local-use /96
		"2002:808:808::1",
		"2001:0:4136:e378:8000:63bf:f7f7:f7f7", // Teredo client 8.8.8.8
		"::ffff:0:808:808",
		"::808:808",
		"2606:4700:4700::1111",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(raw)
			assert.Empty(t, netutil.BlockReason(ip))
			assert.False(t, netutil.IsBlockedIP(ip))
			assert.False(t, netutil.IsCloudMetadataIP(ip))
		})
	}
}

func TestDialBlockReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		addr         string
		blockPrivate bool
		allowlisted  bool
		want         string
	}{
		{"metadata_strict", "169.254.169.254", true, false, netutil.BlockReasonCloudMetadata},
		{"metadata_permissive", "169.254.169.254", false, false, netutil.BlockReasonCloudMetadata},
		{"metadata_allowlisted", "169.254.169.254", true, true, netutil.BlockReasonCloudMetadata},
		{"mapped_metadata_permissive", "::ffff:169.254.169.254", false, false, netutil.BlockReasonCloudMetadata},
		{"nat64_metadata_permissive", "64:ff9b::a9fe:a9fe", false, false, netutil.BlockReasonCloudMetadata},
		{"zoned_metadata_allowlisted", "fd00:ec2::254%eth0", false, true, netutil.BlockReasonCloudMetadata},
		{"private_strict", "10.0.0.5", true, false, netutil.BlockReasonPrivate},
		{"private_permissive", "10.0.0.5", false, false, ""},
		{"private_allowlisted", "10.0.0.5", true, true, ""},
		{"mapped_unspecified_strict", "::ffff:0.0.0.0", true, false, netutil.BlockReasonUnspecified},
		{"nat64_private_strict", "64:ff9b::a00:5", true, false, netutil.BlockReasonPrivate},
		{"public_strict", "8.8.8.8", true, false, ""},
		{"local_use_metadata_permissive", "64:ff9b:1::a9fe:a9fe", false, false, netutil.BlockReasonCloudMetadata},
		{"local_use_48_metadata_allowlisted", "64:ff9b:1:a9fe:a9:fe00::", true, true, netutil.BlockReasonCloudMetadata},
		{"local_use_public_strict", "64:ff9b:1::808:808", true, false, ""},
		{"teredo_metadata_allowlisted", "2001:0:4136:e378:8000:63bf:5601:5601", true, true, netutil.BlockReasonCloudMetadata},
		{"gcp_ipv6_metadata_permissive", "fd20:ce::254", false, false, netutil.BlockReasonCloudMetadata},
		{"ecs_credentials_allowlisted", "169.254.170.2", true, true, netutil.BlockReasonCloudMetadata},
		{"azure_wireserver_strict", "168.63.129.16", true, false, netutil.BlockReasonCloudMetadata},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := netutil.DialBlockReason(netip.MustParseAddr(tt.addr), tt.blockPrivate, tt.allowlisted)
			assert.Equal(t, tt.want, got)
		})
	}
}

// Audit and error text names the address that was judged, so one search
// finds every spelling of it, and keeps the spelling the dial asked for.
func TestBlockedDialDetail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		addr   string
		reason string
		want   string
	}{
		{"plain_ipv4", "10.0.0.5", netutil.BlockReasonPrivate, "ip=10.0.0.5 reason=private"},
		{"plain_ipv6", "fd00::1", netutil.BlockReasonPrivate, "ip=fd00::1 reason=private"},
		{
			"mapped", "::ffff:169.254.169.254", netutil.BlockReasonCloudMetadata,
			"ip=169.254.169.254 reason=cloud_metadata requested=::ffff:169.254.169.254",
		},
		{
			"nat64", "64:ff9b::a9fe:a9fe", netutil.BlockReasonCloudMetadata,
			"ip=169.254.169.254 reason=cloud_metadata requested=64:ff9b::a9fe:a9fe",
		},
		{"zoned", "fe80::1%eth0", netutil.BlockReasonLinkLocal, "ip=fe80::1 reason=link_local requested=fe80::1%eth0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, netutil.BlockedDialDetail(netip.MustParseAddr(tt.addr), tt.reason))
		})
	}
}
