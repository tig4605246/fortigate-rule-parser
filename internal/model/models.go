package model

import "net"

type Protocol string // "tcp", "udp"

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

type AddressObject struct {
	Name    string
	Type    string // "ipmask", "iprange", "fqdn"
	IPNet   *net.IPNet
	StartIP net.IP
	EndIP   net.IP
	FQDN    string
}

type ServiceObject struct {
	Name      string
	Protocol  Protocol
	StartPort int
	EndPort   int
}

type Policy struct {
	ID              string
	Priority        int
	Name            string
	SrcAddrs        []*AddressObject // Pre-expanded group
	DstAddrs        []*AddressObject
	Services        []*ServiceObject
	RawSrcAddrNames []string
	RawDstAddrNames []string
	RawSvcNames     []string
	Action          string // "accept", "deny"
	Enabled         bool
	Schedule        string
}

type Task struct {
	SrcIP        net.IP
	SrcCIDR      string
	DstIP        net.IP
	DstCIDR      string
	DstMeta      map[string]string // For output
	Port         int
	Proto        Protocol
	ServiceLabel string
}

type SimulationResult struct {
	SrcNetworkSegment   string
	DstNetworkSegment   string
	DstGn               string
	DstSite             string
	DstLocation         string
	ServiceLabel        string
	Protocol            string
	Port                int
	Decision            string // "ALLOW", "DENY"
	MatchedPolicyID     string
	MatchedPolicyAction string
	Reason              string
	FlowCount           uint64
}
