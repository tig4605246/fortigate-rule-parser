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
		{
			ID:       "50",
			Priority: 50,
			Action:   "accept",
			Enabled:  false,
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
		DstCIDR: "192.168.1.0/24",
	}

	result := evaluator.Evaluate(task)
	if result.Decision != "DENY" {
		t.Fatalf("expected deny due to higher priority policy, got %s", result.Decision)
	}
	if result.MatchedPolicyID != "100" {
		t.Fatalf("expected policy 100 to match first, got %s", result.MatchedPolicyID)
	}

	implicitTask := &model.Task{
		SrcIP: net.ParseIP("10.0.1.10"),
		DstIP: net.ParseIP("192.168.2.20"),
		Port:  443,
		Proto: model.TCP,
	}
	implicitResult := evaluator.Evaluate(implicitTask)
	if implicitResult.Decision != "DENY" || implicitResult.Reason != "IMPLICIT_DENY" {
		t.Fatalf("expected implicit deny, got decision=%s reason=%s", implicitResult.Decision, implicitResult.Reason)
	}
}

func TestEvaluatorMatchesAllObjects(t *testing.T) {
	policy := model.Policy{
		ID:       "all",
		Priority: 1,
		Action:   "accept",
		Enabled:  true,
		SrcAddrs: []*model.AddressObject{{Name: "all"}},
		DstAddrs: []*model.AddressObject{{Name: "all"}},
		Services: []*model.ServiceObject{{Name: "all"}},
	}
	evaluator := NewEvaluator([]model.Policy{policy})

	result := evaluator.Evaluate(&model.Task{
		SrcIP: net.ParseIP("203.0.113.10"),
		DstIP: net.ParseIP("198.51.100.11"),
		Port:  22,
		Proto: model.TCP,
	})

	if result.Decision != "ALLOW" {
		t.Fatalf("expected allow from all objects policy, got %s", result.Decision)
	}
}

func TestEvaluatorAddressRange(t *testing.T) {
	policy := model.Policy{
		ID:       "range",
		Priority: 1,
		Action:   "accept",
		Enabled:  true,
		SrcAddrs: []*model.AddressObject{
			{
				Name:    "src-range",
				Type:    "iprange",
				StartIP: net.ParseIP("10.0.0.1"),
				EndIP:   net.ParseIP("10.0.0.10"),
			},
		},
		DstAddrs: []*model.AddressObject{{Name: "all"}},
		Services: []*model.ServiceObject{{Name: "all"}},
	}
	evaluator := NewEvaluator([]model.Policy{policy})

	// Match in range
	res := evaluator.Evaluate(&model.Task{SrcIP: net.ParseIP("10.0.0.5"), Port: 80, Proto: model.TCP})
	if res.Decision != "ALLOW" {
		t.Errorf("expected allow for IP in range, got %s", res.Decision)
	}

	// Match start
	res = evaluator.Evaluate(&model.Task{SrcIP: net.ParseIP("10.0.0.1"), Port: 80, Proto: model.TCP})
	if res.Decision != "ALLOW" {
		t.Errorf("expected allow for IP at range start, got %s", res.Decision)
	}

	// Match end
	res = evaluator.Evaluate(&model.Task{SrcIP: net.ParseIP("10.0.0.10"), Port: 80, Proto: model.TCP})
	if res.Decision != "ALLOW" {
		t.Errorf("expected allow for IP at range end, got %s", res.Decision)
	}

	// No match before range
	res = evaluator.Evaluate(&model.Task{SrcIP: net.ParseIP("10.0.0.0"), Port: 80, Proto: model.TCP})
	if res.Decision != "DENY" {
		t.Errorf("expected deny for IP before range, got %s", res.Decision)
	}

	// No match after range
	res = evaluator.Evaluate(&model.Task{SrcIP: net.ParseIP("10.0.0.11"), Port: 80, Proto: model.TCP})
	if res.Decision != "DENY" {
		t.Errorf("expected deny for IP after range, got %s", res.Decision)
	}
}

func TestEvaluatorEmptyListsAndFQDN(t *testing.T) {
	policy := model.Policy{
		ID:       "empty",
		Priority: 1,
		Action:   "accept",
		Enabled:  true,
		SrcAddrs: []*model.AddressObject{}, // Empty
		DstAddrs: []*model.AddressObject{{Name: "fqdn", Type: "fqdn"}},
		Services: []*model.ServiceObject{}, // Empty
	}
	evaluator := NewEvaluator([]model.Policy{policy})

	res := evaluator.Evaluate(&model.Task{SrcIP: net.ParseIP("1.1.1.1"), Port: 80, Proto: model.TCP})
	if res.Decision != "DENY" {
		t.Errorf("expected deny for empty srcaddrs, got %s", res.Decision)
	}
}

func TestEvaluatorServiceProtocols(t *testing.T) {
	policy := model.Policy{
		ID:       "udp",
		Priority: 1,
		Action:   "accept",
		Enabled:  true,
		SrcAddrs: []*model.AddressObject{{Name: "all"}},
		DstAddrs: []*model.AddressObject{{Name: "all"}},
		Services: []*model.ServiceObject{
			{
				Name:      "dns",
				Protocol:  model.UDP,
				StartPort: 53,
				EndPort:   53,
			},
		},
	}
	evaluator := NewEvaluator([]model.Policy{policy})

	// Match UDP
	res := evaluator.Evaluate(&model.Task{Port: 53, Proto: model.UDP})
	if res.Decision != "ALLOW" {
		t.Errorf("expected allow for UDP 53, got %s", res.Decision)
	}

	// Protocol mismatch (TCP 53)
	res = evaluator.Evaluate(&model.Task{Port: 53, Proto: model.TCP})
	if res.Decision != "DENY" {
		t.Errorf("expected deny for TCP 53 mismatch, got %s", res.Decision)
	}
}

func mustParseCIDR(t *testing.T, cidr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("failed to parse CIDR %s: %v", cidr, err)
	}
	return ipNet
}
