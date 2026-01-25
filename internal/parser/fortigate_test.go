package parser

import (
	"strings"
	"testing"

	"static-traffic-analyzer/internal/model"
)

func TestFortiGateParserParsesPoliciesAndFlattensGroups(t *testing.T) {
	config := strings.Join([]string{
		"config firewall address",
		"edit \"addr1\"",
		"set type ipmask",
		"set subnet 10.0.0.0 255.255.255.0",
		"next",
		"edit \"addr-range\"",
		"set type iprange",
		"set start-ip 192.168.1.10",
		"set end-ip 192.168.1.20",
		"next",
		"edit \"fqdn-obj\"",
		"set type fqdn",
		"set fqdn \"example.com\"",
		"next",
		"end",
		"config firewall addrgrp",
		"edit \"grp1\"",
		"set member \"addr1\" \"addr-range\"",
		"next",
		"end",
		"config firewall service custom",
		"edit \"svc1\"",
		"set tcp-portrange 80-81",
		"next",
		"edit \"svc-udp\"",
		"set udp-portrange 5000-5005",
		"next",
		"edit \"svc-eq\"",
		"set tcp-portrange=90",
		"next",
		"end",
		"config firewall service group",
		"edit \"svcgrp\"",
		"set member \"svc1\" \"DNS\" \"svc-udp\"",
		"next",
		"end",
		"config firewall policy",
		"edit 1",
		"set name \"policy one\"",
		"set srcaddr \"grp1\"",
		"set dstaddr \"all\"",
		"set service \"svcgrp\" \"svc-eq\"",
		"set action accept",
		"set status enable",
		"next",
		"edit 2",
		"set srcaddr \"all\"",
		"set dstaddr \"all\"",
		"set service \"all\"",
		"set action deny",
		"set status disable",
		"next",
		"end",
	}, "\n")

	parser := NewFortiGateParser(strings.NewReader(config))
	if err := parser.Parse(); err != nil {
		t.Fatalf("expected parse to succeed, got %v", err)
	}
	if len(parser.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(parser.Policies))
	}

	policy := parser.Policies[0]
	if policy.ID != "1" {
		t.Errorf("expected policy ID 1, got %s", policy.ID)
	}
	if len(policy.SrcAddrs) != 2 {
		t.Fatalf("expected 2 source address objects, got %d", len(policy.SrcAddrs))
	}
	
	foundFQDN := false
	if obj, ok := parser.AddressObjects["fqdn-obj"]; ok {
		if obj.FQDN == "example.com" {
			foundFQDN = true
		}
	}
	if !foundFQDN {
		t.Errorf("FQDN object not parsed correctly")
	}

	if !containsService(policy.Services, 80, model.TCP) || !containsService(policy.Services, 81, model.TCP) {
		t.Fatalf("expected custom tcp service ports 80-81 to be present")
	}
	if !containsService(policy.Services, 5000, model.UDP) {
		t.Fatalf("expected custom udp service port 5000 to be present")
	}
	if !containsService(policy.Services, 90, model.TCP) {
		t.Fatalf("expected custom tcp service port 90 to be present")
	}

	policy2 := parser.Policies[1]
	if policy2.Enabled {
		t.Errorf("expected policy 2 to be disabled")
	}
}

func TestFortiGateParserErrors(t *testing.T) {
	// Test unexpected EOF for various configs
	configs := []string{
		"config firewall address\nedit addr1\nset type ipmask",
		"config firewall addrgrp\nedit grp1\nset member addr1",
		"config firewall service custom\nedit svc1\nset tcp-portrange 80",
		"config firewall service group\nedit svcgrp\nset member svc1",
		"config firewall policy\nedit 1\nset action accept",
	}

	for _, cfg := range configs {
		parser := NewFortiGateParser(strings.NewReader(cfg))
		if err := parser.Parse(); err == nil {
			t.Errorf("expected error for truncated config: %s", cfg)
		}
	}
}

func TestFortiGateParserDetectsCircularAddressGroups(t *testing.T) {
	parser := &FortiGateParser{
		AddressObjects: make(map[string]*model.AddressObject),
		AddrGrps: map[string][]string{
			"A": {"B"},
			"B": {"A"},
		},
	}

	_, err := parser.flattenAddrGroup("A", make(map[string]bool))
	if err == nil {
		t.Fatalf("expected circular dependency error for address groups")
	}
}

func TestFortiGateParserDetectsCircularServiceGroups(t *testing.T) {
	parser := &FortiGateParser{
		ServiceObjects: make(map[string]*model.ServiceObject),
		SvcGrps: map[string][]string{
			"A": {"B"},
			"B": {"A"},
		},
	}

	_, err := parser.flattenSvcGroup("A", make(map[string]bool))
	if err == nil {
		t.Fatalf("expected circular dependency error for service groups")
	}
}

func containsService(services []*model.ServiceObject, port int, protocol model.Protocol) bool {
	for _, svc := range services {
		if svc.Protocol == protocol && port >= svc.StartPort && port <= svc.EndPort {
			return true
		}
	}
	return false
}
