package wellknown

import (
	"bytes"
	"encoding/csv"
	"io"
	"log"
	"strconv"
	"strings"

	_ "embed"

	"static-traffic-analyzer/internal/model"
)

//go:embed well_known_ports.csv
var wellKnownPortsData string

// Ignore all icmp related firewall whitelist
const ICMP = "ALL_ICMP"

type ServiceEntry struct {
	Protocol model.Protocol
	Port     int
}

var serviceRegistry map[string][]ServiceEntry

func init() {
	serviceRegistry = make(map[string][]ServiceEntry)
	reader := csv.NewReader(bytes.NewBufferString(wellKnownPortsData))
	reader.TrimLeadingSpace = true
	// Skip header
	if _, err := reader.Read(); err != nil {
		log.Fatalf("Failed to read header from embedded well_known_ports.csv: %v", err)
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Failed to parse embedded well_known_ports.csv: %v", err)
		}
		if len(record) < 3 {
			continue
		}

		port, err := strconv.Atoi(record[0])
		if err != nil {
			continue // Skip if port is not a valid number
		}

		// Handle TCP service
		tcpName := strings.TrimSpace(record[1])
		if tcpName != "" && tcpName != "N/A" {
			entry := ServiceEntry{
				Protocol: model.TCP,
				Port:     port,
			}
			serviceRegistry[strings.ToUpper(tcpName)] = append(serviceRegistry[strings.ToUpper(tcpName)], entry)
			// Add common alias for DNS
			if tcpName == "domain" {
				serviceRegistry["DNS"] = append(serviceRegistry["DNS"], entry)
			}
		}

		// Handle UDP service
		udpName := strings.TrimSpace(record[2])
		if udpName != "" && udpName != "N/A" {
			entry := ServiceEntry{
				Protocol: model.UDP,
				Port:     port,
			}
			serviceRegistry[strings.ToUpper(udpName)] = append(serviceRegistry[strings.ToUpper(udpName)], entry)
			// Add common alias for DNS
			if udpName == "domain" {
				serviceRegistry["DNS"] = append(serviceRegistry["DNS"], entry)
			}
		}
	}

	ignore_icmp_accept := ServiceEntry{
		Protocol: model.TCP,
		Port:     65535,
	}
	serviceRegistry[strings.ToUpper(ICMP)] = append(serviceRegistry[strings.ToUpper(ICMP)], ignore_icmp_accept)
}

// GetService returns the port and protocol for a well-known service name.
func GetService(name string) ([]ServiceEntry, bool) {
	entry, ok := serviceRegistry[strings.ToUpper(name)]
	return entry, ok
}
