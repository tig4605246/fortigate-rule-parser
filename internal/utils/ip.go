package utils

import "net"

// Inc increments an IP address.
func Inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// CIDRSize returns the number of addresses in a CIDR network.
func CIDRSize(cidr *net.IPNet) uint64 {
	ones, bits := cidr.Mask.Size()
	return 1 << (bits - ones)
}
