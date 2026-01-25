package parser

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"static-traffic-analyzer/internal/model"
)

type InputTraffic struct {
	SrcIPs []*net.IPNet
	DstIPs []Destination
	Ports  []PortInfo
}

type Destination struct {
	IPNet    *net.IPNet
	Metadata map[string]string
}

type PortInfo struct {
	Label    string
	Port     int
	Protocol model.Protocol
}

func ParseInputTraffic(srcFile, dstFile, portsFile io.Reader) (*InputTraffic, error) {
	srcIPs, err := parseSrcFile(srcFile)
	if err != nil {
		return nil, fmt.Errorf("error parsing source file: %w", err)
	}

	dsts, err := parseDstFile(dstFile)
	if err != nil {
		return nil, fmt.Errorf("error parsing destination file: %w", err)
	}

	ports, err := parsePortsFile(portsFile)
	if err != nil {
		return nil, fmt.Errorf("error parsing ports file: %w", err)
	}

	return &InputTraffic{
		SrcIPs: srcIPs,
		DstIPs: dsts,
		Ports:  ports,
	}, nil
}

func parseSrcFile(r io.Reader) ([]*net.IPNet, error) {
	reader := csv.NewReader(r)
	reader.TrimLeadingSpace = true
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("could not read header: %w", err)
	}

	// Find the network segment column
	netSegCol := -1
	for i, col := range header {
		if strings.EqualFold(col, "Network Segment") {
			netSegCol = i
			break
		}
	}
	if netSegCol == -1 {
		return nil, fmt.Errorf("could not find 'Network Segment' column in source file")
	}

	var ipNets []*net.IPNet
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		_, ipnet, err := net.ParseCIDR(record[netSegCol])
		if err != nil {
			// Try parsing as a single IP
			ip := net.ParseIP(record[netSegCol])
			if ip == nil {
				continue // Skip invalid entries
			}
			// Convert single IP to /32 or /128 CIDR
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			ipnet = &net.IPNet{IP: ip, Mask: mask}
		}
		ipNets = append(ipNets, ipnet)
	}
	return ipNets, nil
}

func parseDstFile(r io.Reader) ([]Destination, error) {
	reader := csv.NewReader(r)
	reader.TrimLeadingSpace = true
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("could not read header: %w", err)
	}

	colMap := make(map[string]int)
	for i, colName := range header {
		colMap[strings.ToLower(colName)] = i
	}

	netSegCol, ok := colMap["network segment"]
	if !ok {
		return nil, fmt.Errorf("could not find 'Network Segment' column in destination file")
	}

	var destinations []Destination
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		_, ipnet, err := net.ParseCIDR(record[netSegCol])
		if err != nil {
			ip := net.ParseIP(record[netSegCol])
			if ip == nil {
				continue
			}
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			ipnet = &net.IPNet{IP: ip, Mask: mask}
		}

		meta := make(map[string]string)
		for colName, index := range colMap {
			if index < len(record) {
				meta["dst_"+colName] = record[index]
			}
		}

		destinations = append(destinations, Destination{
			IPNet:    ipnet,
			Metadata: meta,
		})
	}
	return destinations, nil
}

func parsePortsFile(r io.Reader) ([]PortInfo, error) {
	scanner := bufio.NewScanner(r)
	var ports []PortInfo
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Format: ssh,22/tcp or just 22/tcp
		parts := strings.Split(line, ",")
		var label, portProto string
		if len(parts) == 2 {
			label = parts[0]
			portProto = parts[1]
		} else {
			label = parts[0]
			portProto = parts[0]
		}

		protoParts := strings.Split(portProto, "/")
		if len(protoParts) != 2 {
			continue // Skip invalid lines
		}

		port, err := strconv.Atoi(protoParts[0])
		if err != nil {
			continue
		}

		protocol := model.Protocol(strings.ToLower(protoParts[1]))
		if protocol != model.TCP && protocol != model.UDP {
			continue
		}

		ports = append(ports, PortInfo{
			Label:    label,
			Port:     port,
			Protocol: protocol,
		})
	}

	return ports, scanner.Err()
}

// Helper to iterate through all IPs in a CIDR.
// Use with caution on large networks.
func expandCIDR(cidr *net.IPNet) []net.IP {
	var ips []net.IP
	for ip := cidr.IP.Mask(cidr.Mask); cidr.Contains(ip); inc(ip) {
		// Create a copy of the IP to avoid modification issues
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy)
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
