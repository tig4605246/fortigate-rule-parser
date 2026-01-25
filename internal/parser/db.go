package parser

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"static-traffic-analyzer/internal/model"
	"static-traffic-analyzer/pkg/wellknown"

	_ "github.com/go-sql-driver/mysql"
)

type MariaDBParser struct {
	db *sql.DB

	Policies       []model.Policy
	AddressObjects map[string]*model.AddressObject
	ServiceObjects map[string]*model.ServiceObject // Assuming services can be defined in DB as well
	AddrGrps       map[string][]string
	SvcGrps        map[string][]string
}

func NewMariaDBParser(dsn string) (*MariaDBParser, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &MariaDBParser{
		db:             db,
		AddressObjects: make(map[string]*model.AddressObject),
		ServiceObjects: make(map[string]*model.ServiceObject),
		AddrGrps:       make(map[string][]string),
		SvcGrps:        make(map[string][]string),
	}, nil
}

func (p *MariaDBParser) Close() {
	p.db.Close()
}

func (p *MariaDBParser) Parse() error {
	if err := p.loadAddresses(); err != nil {
		return fmt.Errorf("failed to load addresses: %w", err)
	}
	if err := p.loadAddressGroups(); err != nil {
		return fmt.Errorf("failed to load address groups: %w", err)
	}
	// Assuming a service group table exists, similar to address group
	if err := p.loadServiceGroups(); err != nil {
		return fmt.Errorf("failed to load service groups: %w", err)
	}
	if err := p.loadPolicies(); err != nil {
		return fmt.Errorf("failed to load policies: %w", err)
	}

	// The flattening logic is crucial here as well
	return p.flattenGroups()
}

func (p *MariaDBParser) loadAddresses() error {
	rows, err := p.db.Query("SELECT object_name, address_type, subnet, start_ip, end_ip FROM cfg_address")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var name, addrType string
		var subnet, startIP, endIP sql.NullString
		if err := rows.Scan(&name, &addrType, &subnet, &startIP, &endIP); err != nil {
			return err
		}

		addr := &model.AddressObject{Name: name, Type: addrType}
		switch addrType {
		case "ipmask":
			if subnet.Valid {
				_, ipnet, err := net.ParseCIDR(subnet.String)
				if err == nil {
					addr.IPNet = ipnet
				}
			}
		case "iprange":
			if startIP.Valid {
				addr.StartIP = net.ParseIP(startIP.String)
			}
			if endIP.Valid {
				addr.EndIP = net.ParseIP(endIP.String)
			}
		}
		p.AddressObjects[name] = addr
	}
	return nil
}

func (p *MariaDBParser) loadAddressGroups() error {
	rows, err := p.db.Query("SELECT group_name, members FROM cfg_address_group")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var groupName, membersJSON string
		if err := rows.Scan(&groupName, &membersJSON); err != nil {
			return err
		}
		var members []string
		if err := json.Unmarshal([]byte(membersJSON), &members); err == nil {
			p.AddrGrps[groupName] = members
		}
	}
	return nil
}

func (p *MariaDBParser) loadServiceGroups() error {
	rows, err := p.db.Query("SELECT group_name, members FROM cfg_service_group")
	if err != nil {
		// If the table doesn't exist, we can probably ignore this.
		// For now, let's return the error.
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var groupName, membersJSON string
		if err := rows.Scan(&groupName, &membersJSON); err != nil {
			return err
		}
		var members []string
		if err := json.Unmarshal([]byte(membersJSON), &members); err == nil {
			p.SvcGrps[groupName] = members
		}
	}
	return nil
}

func (p *MariaDBParser) loadPolicies() error {
	rows, err := p.db.Query("SELECT priority, policy_id, src_objects, dst_objects, service_objects, action, is_enabled FROM cfg_policy ORDER BY priority ASC")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var policy model.Policy
		var policyID int
		var srcJSON, dstJSON, svcJSON, isEnabled string

		if err := rows.Scan(&policy.Priority, &policyID, &srcJSON, &dstJSON, &svcJSON, &policy.Action, &isEnabled); err != nil {
			return err
		}

		policy.ID = fmt.Sprintf("%d", policyID)
		policy.Enabled = (isEnabled == "enable")

		json.Unmarshal([]byte(srcJSON), &policy.RawSrcAddrNames)
		json.Unmarshal([]byte(dstJSON), &policy.RawDstAddrNames)
		json.Unmarshal([]byte(svcJSON), &policy.RawSvcNames)

		if len(policy.RawSrcAddrNames) == 0 {
			policy.RawSrcAddrNames = []string{"all"}
		}
		if len(policy.RawDstAddrNames) == 0 {
			policy.RawDstAddrNames = []string{"all"}
		}
		if len(policy.RawSvcNames) == 0 {
			policy.RawSvcNames = []string{"all"}
		}

		p.Policies = append(p.Policies, policy)
	}
	sort.SliceStable(p.Policies, func(i, j int) bool {
		return p.Policies[i].Priority < p.Policies[j].Priority
	})

	return nil
}

func (p *MariaDBParser) flattenGroups() error {
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

func (p *MariaDBParser) flattenAddrGroup(name string, visited map[string]bool) ([]*model.AddressObject, error) {
	if strings.EqualFold(name, "all") {
		return []*model.AddressObject{{Name: "all"}}, nil
	}

	if visited[name] {
		return nil, fmt.Errorf("circular dependency detected in address group '%s'", name)
	}
	visited[name] = true
	defer func() {
		delete(visited, name)
	}()

	var results []*model.AddressObject

	if addr, ok := p.AddressObjects[name]; ok {
		results = append(results, addr)
	}

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

func (p *MariaDBParser) flattenSvcGroup(name string, visited map[string]bool) ([]*model.ServiceObject, error) {
	if strings.EqualFold(name, "all") {
		return []*model.ServiceObject{{Name: "all"}}, nil
	}

	if visited[name] {
		return nil, fmt.Errorf("circular dependency detected in service group '%s'", name)
	}
	visited[name] = true
	defer func() {
		delete(visited, name)
	}()

	var results []*model.ServiceObject
	var found bool

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

	// If not found, check well-known services
	if !found {
		if wkServices, ok := wellknown.GetService(name); ok {
			for _, wk := range wkServices {
				results = append(results, &model.ServiceObject{
					Name:      name,
					Protocol:  wk.Protocol,
					StartPort: wk.Port,
					EndPort:   wk.Port,
				})
			}
			found = true
		}
	}

	// If still not found, try to parse as ad-hoc "tcp_8001-8004"
	if !found {
		parts := strings.Split(name, "_")
		if len(parts) == 2 {
			protoStr := strings.ToLower(parts[0])
			protocol := model.Protocol(protoStr)
			if protocol == model.TCP || protocol == model.UDP {
				portRange := parts[1]
				if portParts := strings.Split(portRange, "-"); len(portParts) > 0 {
					start, err1 := strconv.Atoi(portParts[0])
					end := start
					var err2 error
					if len(portParts) == 2 {
						end, err2 = strconv.Atoi(portParts[1])
					}
					if err1 == nil && err2 == nil {
						results = append(results, &model.ServiceObject{
							Name:      name,
							Protocol:  protocol,
							StartPort: start,
							EndPort:   end,
						})
					}
				}
			}
		}
	}

	return results, nil
}
