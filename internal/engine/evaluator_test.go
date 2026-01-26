package engine

import (
	"net"
	"testing"

	"static-traffic-analyzer/internal/model"
)

func TestEvaluatorEvaluateHonorsPriorityAndImplicitDeny(t *testing.T) {
	srcAddr := &model.AddressObject{
		Name:  "src-net",
		Type:  "ipmask",
		IPNet: mustParseCIDR(t, "10.0.0.0/24"),
	}
	dstAddr := &model.AddressObject{
		Name:  "dst-net",
		Type:  "ipmask",
		IPNet: mustParseCIDR(t, "192.168.1.0/24"),
	}
	service := &model.ServiceObject{
		Name:      "http",
		Protocol:  model.TCP,
		StartPort: 80,
		EndPort:   80,
	}

	policies := []model.Policy{
		{
			ID:       "200",
			Priority: 200,
			Action:   "accept",
			Enabled:  true,
			SrcAddrs: []*model.AddressObject{srcAddr},
			DstAddrs: []*model.AddressObject{dstAddr},
			Services: []*model.ServiceObject{service},
		},
		{
			ID:       "100",
			Priority: 100,
			Action:   "deny",
			Enabled:  true,
			SrcAddrs: []*model.AddressObject{srcAddr},
			DstAddrs: []*model.AddressObject{dstAddr},
			Services: []*model.ServiceObject{service},
		},
	}

	evaluator := NewEvaluator(policies)

	task := &model.Task{
		SrcIP:   net.ParseIP("10.0.0.10"),
		DstIP:   net.ParseIP("192.168.1.20"),
		Port:    80,
		Proto:   model.TCP,
	}

	result := evaluator.Evaluate(task)
	if result.Decision != "DENY" || result.MatchedPolicyID != "100" {
		t.Fatalf("expected DENY from policy 100, got %s (ID %s)", result.Decision, result.MatchedPolicyID)
	}
}

func TestEvaluatorPrecheckComprehensive(t *testing.T) {
	policies := []model.Policy{
		{
			ID:       "P1-Partial-Accept",
			Priority: 10,
			Action:   "accept",
			Enabled:  true,
			SrcAddrs: []*model.AddressObject{{Name: "small-src", Type: "ipmask", IPNet: mustParseCIDR(t, "10.0.0.0/24")}},
			DstAddrs: []*model.AddressObject{{Name: "all"}},
			Services: []*model.ServiceObject{{Name: "all"}},
		},
		{
			ID:       "P2-Full-Deny",
			Priority: 20,
			Action:   "deny",
			Enabled:  true,
			SrcAddrs: []*model.AddressObject{{Name: "deny-src", Type: "ipmask", IPNet: mustParseCIDR(t, "172.16.0.0/16")}},
			DstAddrs: []*model.AddressObject{{Name: "all"}},
			Services: []*model.ServiceObject{{Name: "ssh", Protocol: model.TCP, StartPort: 22, EndPort: 22}},
		},
		{
			ID:       "P3-Full-Accept",
			Priority: 30,
			Action:   "accept",
			Enabled:  true,
			SrcAddrs: []*model.AddressObject{{Name: "allow-src", Type: "ipmask", IPNet: mustParseCIDR(t, "172.16.0.0/12")}},
			DstAddrs: []*model.AddressObject{{Name: "all"}},
			Services: []*model.ServiceObject{{Name: "all"}},
		},
	}
	evaluator := NewEvaluator(policies)

	tests := []struct {
		name     string
		src      string
		dst      string
		port     int
		proto    model.Protocol
		expected PrecheckStatus
		expID    string
	}{
		{
			name:     "Full match P1 (Partial Coverage) -> EXPAND",
			src:      "10.0.0.0/16",
			dst:      "192.168.1.1/32",
			port:     80,
			proto:    model.TCP,
			expected: StatusExpand,
			expID:    "P1-Partial-Accept",
		},
		{
			name:     "Contained in P1 -> ALLOW_ALL",
			src:      "10.0.0.128/25",
			dst:      "1.1.1.1/32",
			port:     443,
			proto:    model.TCP,
			expected: StatusAllowAll,
			expID:    "P1-Partial-Accept",
		},
		{
			name:     "Contained in P2 -> SKIP (Deny)",
			src:      "172.16.5.0/24",
			dst:      "8.8.8.8/32",
			port:     22,
			proto:    model.TCP,
			expected: StatusSkip,
			expID:    "P2-Full-Deny",
		},
		{
			name:     "Misses P2, contained in P3 -> ALLOW_ALL",
			src:      "172.16.5.0/24",
			dst:      "8.8.8.8/32",
			port:     80,
			proto:    model.TCP,
			expected: StatusAllowAll,
			expID:    "P3-Full-Accept",
		},
		{
			name:     "Family mismatch -> SKIP (Implicit Deny)",
			src:      "2001:db8::/32",
			dst:      "1.1.1.1/32",
			port:     80,
			proto:    model.TCP,
			expected: StatusSkip,
			expID:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, policy, _ := evaluator.Precheck(mustParseCIDR(t, tt.src), mustParseCIDR(t, tt.dst), tt.port, tt.proto)
			if status != tt.expected {
				t.Errorf("Precheck status mismatch: got %s, want %s", status, tt.expected)
			}
			if tt.expID != "" && (policy == nil || policy.ID != tt.expID) {
				t.Errorf("Matched policy ID mismatch: got %v, want %s", policy, tt.expID)
			}
		})
	}
}

func mustParseCIDR(t *testing.T, cidr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("failed to parse CIDR %s: %v", cidr, err)
	}
	return ipNet
}
