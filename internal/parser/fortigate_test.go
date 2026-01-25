package parser

import (
	"strings"
	"testing"

	"static-traffic-analyzer/internal/model"
)

func TestFortiGateParserParsesPoliciesAndFlattensGroups(t *testing.T) {
	// This test validates parsing of address objects, groups, services, and policies,
	// including flattening groups with well-known services.
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
		"end",
		"config firewall service group",
		"edit \"svcgrp\"",
		"set member \"svc1\" \"DNS\"",
		"next",
		"end",
		"config firewall policy",
		"edit 1",
		"set name \"policy one\"",
		"set srcaddr \"grp1\"",
		"set dstaddr \"all\"",
		"set service \"svcgrp\"",
		"set action accept",
		"set status enable",
		"next",
		"end",
	}, "\n")

	parser := NewFortiGateParser(strings.NewReader(config))
	if err := parser.Parse(); err != nil {
		t.Fatalf("expected parse to succeed, got %v", err)
	}
	if len(parser.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(parser.Policies))
	}

	policy := parser.Policies[0]
	if len(policy.SrcAddrs) != 2 {
		t.Fatalf("expected 2 source address objects, got %d", len(policy.SrcAddrs))
	}
	if len(policy.DstAddrs) != 1 || policy.DstAddrs[0].Name != "all" {
		t.Fatalf("expected destination to include 'all', got %#v", policy.DstAddrs)
	}

	if !containsService(policy.Services, 80, model.TCP) || !containsService(policy.Services, 81, model.TCP) {
		t.Fatalf("expected custom tcp service ports 80-81 to be present, got %#v", policy.Services)
	}
	if !containsService(policy.Services, 53, model.TCP) && !containsService(policy.Services, 53, model.UDP) {
		t.Fatalf("expected DNS well-known service to be present, got %#v", policy.Services)
	}
}

func TestFortiGateParserDetectsCircularAddressGroups(t *testing.T) {
	// This test ensures the parser detects circular dependencies in address groups.
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
	// This test ensures the parser detects circular dependencies in service groups.
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
	// Helper ensures test assertions on flattened services are concise and consistent.
	for _, svc := range services {
		if svc.Protocol == protocol && port >= svc.StartPort && port <= svc.EndPort {
			return true
		}
	}
	return false
}
