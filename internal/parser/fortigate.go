package parser

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"static-traffic-analyzer/internal/model"
	"static-traffic-analyzer/pkg/wellknown"
)

type FortiGateParser struct {
	scanner *bufio.Scanner

	Policies       []model.Policy
	AddressObjects map[string]*model.AddressObject
	ServiceObjects map[string]*model.ServiceObject
	AddrGrps       map[string][]string
	SvcGrps        map[string][]string
}

func NewFortiGateParser(reader io.Reader) *FortiGateParser {
	return &FortiGateParser{
		scanner:        bufio.NewScanner(reader),
		AddressObjects: make(map[string]*model.AddressObject),
		ServiceObjects: make(map[string]*model.ServiceObject),
		AddrGrps:       make(map[string][]string),
		SvcGrps:        make(map[string][]string),
	}
}

func (p *FortiGateParser) Parse() error {
	for p.scanner.Scan() {
		line := strings.TrimSpace(p.scanner.Text())
		switch {
		case strings.HasPrefix(line, "config firewall address"):
			if err := p.parseAddressConfig(); err != nil {
				return fmt.Errorf("failed to parse firewall address config: %w", err)
			}
		case strings.HasPrefix(line, "config firewall addrgrp"):
			if err := p.parseAddrGrpConfig(); err != nil {
				return fmt.Errorf("failed to parse firewall addrgrp config: %w", err)
			}
		case strings.HasPrefix(line, "config firewall service custom"):
			if err := p.parseServiceCustomConfig(); err != nil {
				return fmt.Errorf("failed to parse firewall service custom config: %w", err)
			}
		case strings.HasPrefix(line, "config firewall service group"):
			if err := p.parseServiceGroupConfig(); err != nil {
				return fmt.Errorf("failed to parse firewall service group config: %w", err)
			}
		case strings.HasPrefix(line, "config firewall policy"):
			if err := p.parsePolicyConfig(); err != nil {
				return fmt.Errorf("failed to parse firewall policy config: %w", err)
			}
		}
	}
	if err := p.scanner.Err(); err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}
	return p.flattenGroups()
}

func (p *FortiGateParser) parseAddressConfig() error {
	var currentObject *model.AddressObject
	for p.scanner.Scan() {
		line := strings.TrimSpace(p.scanner.Text())
		if line == "end" {
			return nil
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		switch parts[0] {
		case "edit":
			name := unquote(parts[1])
			currentObject = &model.AddressObject{Name: name}
			p.AddressObjects[name] = currentObject
		case "set":
			if currentObject == nil {
				continue
			}
			switch parts[1] {
			case "type":
				currentObject.Type = parts[2]
			case "subnet":
				// Fortigate configs can have ipmask without a proper CIDR suffix.
				// e.g., set subnet 1.1.1.1 255.255.255.0
				mask := net.IPMask(net.ParseIP(parts[3]).To4())
				prefixLen, _ := mask.Size()
				_, ipnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", parts[2], prefixLen))
				if err == nil {
					currentObject.IPNet = ipnet
				}
			case "start-ip":
				currentObject.StartIP = net.ParseIP(parts[2])
			case "end-ip":
				currentObject.EndIP = net.ParseIP(parts[2])
			case "fqdn":
				currentObject.FQDN = unquote(parts[2])
			}
		case "next":
			currentObject = nil
		}
	}
	return io.ErrUnexpectedEOF
}

func (p *FortiGateParser) parseAddrGrpConfig() error {
	var currentGroup string
	for p.scanner.Scan() {
		line := strings.TrimSpace(p.scanner.Text())
		if line == "end" {
			return nil
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		switch parts[0] {
		case "edit":
			currentGroup = unquote(parts[1])
		case "set":
			if currentGroup != "" && parts[1] == "member" {
				var members []string
				for _, member := range parts[2:] {
					members = append(members, unquote(member))
				}
				p.AddrGrps[currentGroup] = members
			}
		case "next":
			currentGroup = ""
		}
	}
	return io.ErrUnexpectedEOF
}

func (p *FortiGateParser) parseServiceCustomConfig() error {
	var currentService *model.ServiceObject
	for p.scanner.Scan() {
		line := strings.TrimSpace(p.scanner.Text())
		if line == "end" {
			return nil
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		switch parts[0] {
		case "edit":
			name := unquote(parts[1])
			currentService = &model.ServiceObject{Name: name}
			p.ServiceObjects[name] = currentService
		case "set":
			if currentService == nil {
				continue
			}
			if strings.Contains(line, "portrange") {
				// Handles "set tcp-portrange 8001-8004" and "set tcp-portrange=8001-8004"
				line = strings.Replace(line, "=", " ", -1)
				parts = strings.Fields(line)
				portRange := parts[2]

				ports := strings.Split(portRange, "-")
				startPort, _ := strconv.Atoi(ports[0])
				endPort := startPort
				if len(ports) > 1 {
					endPort, _ = strconv.Atoi(ports[1])
				}
				currentService.StartPort = startPort
				currentService.EndPort = endPort
				if strings.HasPrefix(parts[1], "tcp") {
					currentService.Protocol = model.TCP
				} else if strings.HasPrefix(parts[1], "udp") {
					currentService.Protocol = model.UDP
				}
			}
		case "next":
			currentService = nil
		}
	}
	return io.ErrUnexpectedEOF
}

func (p *FortiGateParser) parseServiceGroupConfig() error {
	var currentGroup string
	for p.scanner.Scan() {
		line := strings.TrimSpace(p.scanner.Text())
		if line == "end" {
			return nil
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		switch parts[0] {
		case "edit":
			currentGroup = unquote(parts[1])
		case "set":
			if currentGroup != "" && parts[1] == "member" {
				var members []string
				for _, member := range parts[2:] {
					members = append(members, unquote(member))
				}
				p.SvcGrps[currentGroup] = members
			}
		case "next":
			currentGroup = ""
		}
	}
	return io.ErrUnexpectedEOF
}

func (p *FortiGateParser) parsePolicyConfig() error {
	var currentPolicy *model.Policy
	var policyIndex int = -1

	for p.scanner.Scan() {
		line := strings.TrimSpace(p.scanner.Text())
		if line == "end" {
			return nil
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		switch parts[0] {
		case "edit":
			id := parts[1]
			priority, _ := strconv.Atoi(id)
			p.Policies = append(p.Policies, model.Policy{ID: id, Priority: priority})
			policyIndex = len(p.Policies) - 1
			currentPolicy = &p.Policies[policyIndex]
		case "set":
			if currentPolicy == nil {
				continue
			}

			// Join parts from index 2 to the end, then split by quotes
			// This handles names with spaces like "My Policy Name"
			rawArgs := strings.TrimSpace(strings.Join(parts[2:], " "))
			args := strings.Split(rawArgs, `" "`)
			for i, arg := range args {
				args[i] = unquote(arg)
			}

			switch parts[1] {
			case "name":
				currentPolicy.Name = unquote(strings.Join(parts[2:], " "))
			case "srcaddr":
				currentPolicy.RawSrcAddrNames = append(currentPolicy.RawSrcAddrNames, args...)
			case "dstaddr":
				currentPolicy.RawDstAddrNames = append(currentPolicy.RawDstAddrNames, args...)
			case "service":
				currentPolicy.RawSvcNames = append(currentPolicy.RawSvcNames, args...)
			case "action":
				currentPolicy.Action = parts[2]
			case "status":
				currentPolicy.Enabled = (parts[2] == "enable")
			}
		case "next":
			if currentPolicy != nil {
				if len(currentPolicy.RawSrcAddrNames) == 0 {
					currentPolicy.RawSrcAddrNames = []string{"all"}
				}
				if len(currentPolicy.RawDstAddrNames) == 0 {
					currentPolicy.RawDstAddrNames = []string{"all"}
				}
				if len(currentPolicy.RawSvcNames) == 0 {
					currentPolicy.RawSvcNames = []string{"all"}
				}
			}
			currentPolicy = nil
			policyIndex = -1
		}
	}
	return io.ErrUnexpectedEOF
}

func (p *FortiGateParser) flattenGroups() error {
	for i := range p.Policies {
		policy := &p.Policies[i]

		// Flatten SrcAddrs
		if len(policy.RawSrcAddrNames) > 0 {
			var addrs []*model.AddressObject
			for _, name := range policy.RawSrcAddrNames {
				resolved, err := p.flattenAddrGroup(name, make(map[string]bool))
				if err != nil {
					return fmt.Errorf("policy %s: failed to flatten srcaddr '%s': %w", policy.ID, name, err)
				}
				addrs = append(addrs, resolved...)
			}
			policy.SrcAddrs = addrs
		}

		// Flatten DstAddrs
		if len(policy.RawDstAddrNames) > 0 {
			var addrs []*model.AddressObject
			for _, name := range policy.RawDstAddrNames {
				resolved, err := p.flattenAddrGroup(name, make(map[string]bool))
				if err != nil {
					return fmt.Errorf("policy %s: failed to flatten dstaddr '%s': %w", policy.ID, name, err)
				}
				addrs = append(addrs, resolved...)
			}
			policy.DstAddrs = addrs
		}

		// Flatten Services
		if len(policy.RawSvcNames) > 0 {
			var svcs []*model.ServiceObject
			for _, name := range policy.RawSvcNames {
				resolved, err := p.flattenSvcGroup(name, make(map[string]bool))
				if err != nil {
					return fmt.Errorf("policy %s: failed to flatten service '%s': %w", policy.ID, name, err)
				}
				svcs = append(svcs, resolved...)
			}
			policy.Services = svcs
		}
	}
	return nil
}

func (p *FortiGateParser) flattenAddrGroup(name string, visited map[string]bool) ([]*model.AddressObject, error) {
	if strings.EqualFold(name, "all") {
		return []*model.AddressObject{{Name: "all"}}, nil
	}

	if visited[name] {
		return nil, fmt.Errorf("circular dependency detected in address group '%s'", name)
	}
	visited[name] = true
	defer func() {
		delete(visited, name)
	}() // Ensure visited is cleaned up

	var results []*model.AddressObject

	// Is it a direct address object?
	if addr, ok := p.AddressObjects[name]; ok {
		results = append(results, addr)
	}

	// Is it an address group?
	if members, ok := p.AddrGrps[name]; ok {
		for _, memberName := range members {
			memberAddrs, err := p.flattenAddrGroup(memberName, visited)
			if err != nil {
				return nil, err
			}
			results = append(results, memberAddrs...)
		}
	}

	return results, nil
}

func (p *FortiGateParser) flattenSvcGroup(name string, visited map[string]bool) ([]*model.ServiceObject, error) {
	if strings.EqualFold(name, "all") {
		return []*model.ServiceObject{{Name: "all"}}, nil
	}

	if visited[name] {
		return nil, fmt.Errorf("circular dependency detected in service group '%s'", name)
	}
	visited[name] = true
	defer func() {
		delete(visited, name)
	}() // Ensure visited is cleaned up

	var results []*model.ServiceObject
	found := false

	// Is it a direct service object?
	if svc, ok := p.ServiceObjects[name]; ok {
		results = append(results, svc)
		found = true
	}

	// Is it a service group?
	if members, ok := p.SvcGrps[name]; ok {
		for _, memberName := range members {
			memberSvcs, err := p.flattenSvcGroup(memberName, visited)
			if err != nil {
				return nil, err
			}
			results = append(results, memberSvcs...)
		}
		found = true
	}

	// If not found in custom objects or groups, check well-known services
	if !found {
		if wkServices, ok := wellknown.GetService(name); ok {
			for _, wk := range wkServices {
				results = append(results, &model.ServiceObject{
					Name:      name,
					Protocol:  wk.Protocol,
					StartPort: wk.StartPort,
					EndPort:   wk.EndPort,
				})
			}
		}
	}

	return results, nil
}

func unquote(s string) string {
	return strings.Trim(s, `"`)
}
