package utils

import (
	"net"
	"testing"
)

func TestIncIncrementsIPv4Address(t *testing.T) {
	// This test validates incrementing an IPv4 address across a byte boundary.
	ip := net.ParseIP("192.168.1.255")
	if ip == nil {
		t.Fatalf("expected valid IP")
	}
	Inc(ip)
	if ip.String() != "192.168.2.0" {
		t.Fatalf("expected incremented IP to be 192.168.2.0, got %s", ip.String())
	}
}

func TestCIDRSizeCalculatesCorrectly(t *testing.T) {
	// This test checks CIDR size for IPv4 and IPv6 boundaries to avoid off-by-one errors.
	_, ipv4Net, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatalf("expected valid CIDR, got %v", err)
	}
	if size := CIDRSize(ipv4Net); size != 256 {
		t.Fatalf("expected /24 to have size 256, got %d", size)
	}

	_, ipv6Net, err := net.ParseCIDR("2001:db8::/128")
	if err != nil {
		t.Fatalf("expected valid IPv6 CIDR, got %v", err)
	}
	if size := CIDRSize(ipv6Net); size != 1 {
		t.Fatalf("expected /128 to have size 1, got %d", size)
	}
}
