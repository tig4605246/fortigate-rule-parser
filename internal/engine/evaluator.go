package engine

import (
	"net"
	"sort"

	"static-traffic-analyzer/internal/model"
)

type Evaluator struct {
	Policies []model.Policy
}

func NewEvaluator(policies []model.Policy) *Evaluator {
	// Ensure policies are sorted by priority for "first match wins" logic
	sort.SliceStable(policies, func(i, j int) bool {
		return policies[i].Priority < policies[j].Priority
	})
	return &Evaluator{Policies: policies}
}

// Evaluate checks a single traffic task against the loaded policies.
func (e *Evaluator) Evaluate(task *model.Task) model.SimulationResult {
	for _, policy := range e.Policies {
		if !policy.Enabled {
			continue
		}

		if e.matches(&policy, task) {
			decision := "DENY"
			reason := "MATCH_POLICY_DENY"
			if policy.Action == "accept" {
				decision = "ALLOW"
				reason = "MATCH_POLICY_ACCEPT"
			}
			return model.SimulationResult{
				Decision:            decision,
				MatchedPolicyID:     policy.ID,
				MatchedPolicyAction: policy.Action,
				Reason:              reason,
			}
		}
	}

	return model.SimulationResult{
		Decision: "DENY",
		Reason:   "IMPLICIT_DENY",
	}
}

// matches determines if a task matches a policy's criteria.
func (e *Evaluator) matches(policy *model.Policy, task *model.Task) bool {
	return e.matchAddr(policy.SrcAddrs, task.SrcIP) &&
		e.matchAddr(policy.DstAddrs, task.DstIP) &&
		e.matchSvc(policy.Services, task)
}

// matchAddr checks if an IP is contained within a list of address objects.
func (e *Evaluator) matchAddr(addrs []*model.AddressObject, ip net.IP) bool {
	if len(addrs) == 0 {
		return false
	}
	for _, addr := range addrs {
		// Check for the special "all" object
		if addr.Name == "all" {
			return true
		}
		switch addr.Type {
		case "ipmask":
			if addr.IPNet != nil && addr.IPNet.Contains(ip) {
				return true
			}
		case "iprange":
			if addr.StartIP != nil && addr.EndIP != nil {
				// Compare bytes directly
				if bytesCompare(ip, addr.StartIP) >= 0 && bytesCompare(ip, addr.EndIP) <= 0 {
					return true
				}
			}
		case "fqdn":
			// FQDN resolution is out of scope for static analysis.
			continue
		}
	}
	return false
}

// matchSvc checks if a task's service (port/protocol) matches a list of service objects.
func (e *Evaluator) matchSvc(svcs []*model.ServiceObject, task *model.Task) bool {
	if len(svcs) == 0 {
		return false
	}
	for _, svc := range svcs {
		// Check for the special "all" object
		if svc.Name == "all" {
			return true
		}

		if svc.Protocol == task.Proto &&
			task.Port >= svc.StartPort &&
			task.Port <= svc.EndPort {
			return true
		}
	}
	return false
}

// bytesCompare is a helper for comparing net.IP addresses.
func bytesCompare(a, b net.IP) int {
	a = a.To16()
	b = b.To16()
	for i := 0; i < len(a); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
