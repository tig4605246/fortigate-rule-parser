package engine

import (
	"net"
	"sort"
	"strconv"

	"static-traffic-analyzer/internal/model"
)

type PrecheckStatus string

const (
	StatusSkip     PrecheckStatus = "SKIP"
	StatusAllowAll PrecheckStatus = "ALLOW_ALL"
	StatusExpand   PrecheckStatus = "EXPAND"
)

type Evaluator struct {
	Policies      []model.Policy
	precheckIndex map[string][]*model.Policy
	broadPolicies []*model.Policy
}

func NewEvaluator(policies []model.Policy) *Evaluator {
	sort.SliceStable(policies, func(i, j int) bool {
		return policies[i].Priority < policies[j].Priority
	})
	evaluator := &Evaluator{
		Policies:      policies,
		precheckIndex: make(map[string][]*model.Policy),
	}
	evaluator.buildPrecheckIndex()
	return evaluator
}

func (e *Evaluator) buildPrecheckIndex() {
	for i := range e.Policies {
		policy := &e.Policies[i]
		if !policy.Enabled {
			continue
		}

		isBroad := false
		for _, svc := range policy.Services {
			if svc.Name == "all" || (svc.EndPort-svc.StartPort) > 100 {
				isBroad = true
				break
			}
		}

		if isBroad {
			e.broadPolicies = append(e.broadPolicies, policy)
			continue
		}

		for _, svc := range policy.Services {
			for p := svc.StartPort; p <= svc.EndPort; p++ {
				key := precheckKey(p, svc.Protocol)
				e.precheckIndex[key] = append(e.precheckIndex[key], policy)
			}
		}
	}
}

func (e *Evaluator) Evaluate(task *model.Task) model.SimulationResult {
	for i := range e.Policies {
		policy := &e.Policies[i]
		if !policy.Enabled {
			continue
		}
		if e.matches(policy, task) {
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
				SrcIP:               task.SrcIP.String(),
				DstIP:               task.DstIP.String(),
				Reason:              reason,
				FlowCount:           1,
			}
		}
	}
	return model.SimulationResult{
		Decision:  "DENY",
		Reason:    "IMPLICIT_DENY",
		SrcIP:     task.SrcIP.String(),
		DstIP:     task.DstIP.String(),
		FlowCount: 1,
	}
}

func (e *Evaluator) Precheck(srcCIDR, dstCIDR *net.IPNet, port int, proto model.Protocol) (PrecheckStatus, *model.Policy, string) {
	if srcCIDR == nil || dstCIDR == nil {
		return StatusExpand, nil, "PRECHECK_INVALID_CIDR"
	}

	key := precheckKey(port, proto)
	_ = e.precheckIndex[key]
	
	// We need to merge specific and broad policies while maintaining priority.
	// Since e.Policies is already sorted, we can just iterate through it but skip 
	// policies that don't match the port/proto.
	for i := range e.Policies {
		policy := &e.Policies[i]
		if !policy.Enabled { continue }
		
		matchesSvc := false
		for _, svc := range policy.Services {
			if svc.Name == "all" || (svc.Protocol == proto && port >= svc.StartPort && port <= svc.EndPort) {
				matchesSvc = true
				break
			}
		}
		if !matchesSvc { continue }

		srcRel := addrRelation(policy.SrcAddrs, srcCIDR)
		if srcRel == relNone { continue }
		dstRel := addrRelation(policy.DstAddrs, dstCIDR)
		if dstRel == relNone { continue }

		if srcRel != relFull || dstRel != relFull {
			return StatusExpand, policy, "PRECHECK_PARTIAL"
		}

		if policy.Action == "accept" {
			return StatusAllowAll, policy, "PRECHECK_ALLOW_ALL"
		}
		return StatusSkip, policy, "PRECHECK_DENY"
	}

	return StatusSkip, nil, "PRECHECK_IMPLICIT_DENY"
}

func (e *Evaluator) matches(policy *model.Policy, task *model.Task) bool {
	return e.matchAddr(policy.SrcAddrs, task.SrcIP) &&
		e.matchAddr(policy.DstAddrs, task.DstIP) &&
		e.matchSvc(policy.Services, task)
}

func (e *Evaluator) matchAddr(addrs []*model.AddressObject, ip net.IP) bool {
	if len(addrs) == 0 { return false }
	for _, addr := range addrs {
		if addr.Name == "all" { return true }
		switch addr.Type {
		case "ipmask":
			if addr.IPNet != nil && addr.IPNet.Contains(ip) { return true }
		case "iprange":
			if addr.StartIP != nil && addr.EndIP != nil {
				if bytesCompare(ip, addr.StartIP) >= 0 && bytesCompare(ip, addr.EndIP) <= 0 { return true }
			}
		}
	}
	return false
}

func (e *Evaluator) matchSvc(svcs []*model.ServiceObject, task *model.Task) bool {
	if len(svcs) == 0 { return false }
	for _, svc := range svcs {
		if svc.Name == "all" { return true }
		if svc.Protocol == task.Proto && task.Port >= svc.StartPort && task.Port <= svc.EndPort { return true }
	}
	return false
}

type cidrRelation int
const (
	relNone cidrRelation = iota
	relPartial
	relFull
)

func addrRelation(addrs []*model.AddressObject, cidr *net.IPNet) cidrRelation {
	if cidr == nil || len(addrs) == 0 { return relNone }
	cidrStart, cidrEnd := cidrRange(cidr)
	if cidrStart == nil || cidrEnd == nil { return relNone }

	partialFound := false
	for _, addr := range addrs {
		if addr == nil { continue }
		if addr.Name == "all" { return relFull }
		addrStart, addrEnd := addressRange(addr)
		if addrStart == nil || addrEnd == nil { continue }
		if !sameIPFamily(addrStart, cidrStart) { continue }

		rel := rangeRelation(addrStart, addrEnd, cidrStart, cidrEnd)
		if rel == relFull { return relFull }
		if rel == relPartial { partialFound = true }
	}
	if partialFound { return relPartial }
	return relNone
}

func rangeRelation(rangeStart, rangeEnd, cidrStart, cidrEnd net.IP) cidrRelation {
	if bytesCompare(rangeEnd, cidrStart) < 0 || bytesCompare(rangeStart, cidrEnd) > 0 { return relNone }
	if bytesCompare(rangeStart, cidrStart) <= 0 && bytesCompare(rangeEnd, cidrEnd) >= 0 { return relFull }
	return relPartial
}

func sameIPFamily(a, b net.IP) bool {
	return (a.To4() != nil) == (b.To4() != nil)
}

func addressRange(addr *model.AddressObject) (net.IP, net.IP) {
	switch addr.Type {
	case "ipmask":
		if addr.IPNet == nil { return nil, nil }
		return cidrRange(addr.IPNet)
	case "iprange":
		if addr.StartIP == nil || addr.EndIP == nil { return nil, nil }
		return addr.StartIP.To16(), addr.EndIP.To16()
	default:
		return nil, nil
	}
}

func cidrRange(cidr *net.IPNet) (net.IP, net.IP) {
	if cidr == nil { return nil, nil }
	ip := cidr.IP.To16()
	mask := cidr.Mask
	if ip == nil || mask == nil { return nil, nil }

	start := ip.Mask(mask).To16()
	end := make(net.IP, len(start))
	copy(end, start)
	
	// Adjust mask for To16 consistency
	if len(mask) == 4 {
		// IPv4 mask in 16-byte representation should be applied to the last 4 bytes
		for i := 0; i < 4; i++ {
			end[12+i] |= ^mask[i]
		}
	} else {
		for i := 0; i < len(mask); i++ {
			end[i] |= ^mask[i]
		}
	}
	return start, end
}

func precheckKey(port int, proto model.Protocol) string {
	return string(proto) + ":" + strconv.Itoa(port)
}

func bytesCompare(a, b net.IP) int {
	a = a.To16()
	b = b.To16()
	for i := 0; i < 16; i++ {
		if a[i] < b[i] { return -1 }
		if a[i] > b[i] { return 1 }
	}
	return 0
}
