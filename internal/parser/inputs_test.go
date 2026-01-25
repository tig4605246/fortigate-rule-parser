package parser

import (
	"strings"
	"testing"

	"static-traffic-analyzer/internal/model"
)

func TestParseInputTrafficParsesAllInputs(t *testing.T) {
	// This test validates the happy path where source, destination, and port inputs are parsed together.
	srcCSV := strings.NewReader("Network Segment\n10.0.0.0/24\n")
	dstCSV := strings.NewReader("Network Segment,Site\n192.168.1.5,DC1\n")
	portsTXT := strings.NewReader("ssh,22/tcp\n")

	traffic, err := ParseInputTraffic(srcCSV, dstCSV, portsTXT)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(traffic.SrcIPs) != 1 {
		t.Fatalf("expected 1 source IP, got %d", len(traffic.SrcIPs))
	}
	if len(traffic.DstIPs) != 1 {
		t.Fatalf("expected 1 destination, got %d", len(traffic.DstIPs))
	}
	if len(traffic.Ports) != 1 {
		t.Fatalf("expected 1 port entry, got %d", len(traffic.Ports))
	}
	if traffic.Ports[0].Protocol != model.TCP {
		t.Fatalf("expected TCP protocol, got %s", traffic.Ports[0].Protocol)
	}
	if traffic.DstIPs[0].Metadata["dst_site"] != "DC1" {
		t.Fatalf("expected destination metadata to preserve site column, got %#v", traffic.DstIPs[0].Metadata)
	}
}

func TestParseSrcFileHandlesInvalidAndSingleIPEntries(t *testing.T) {
	// This test confirms invalid IP entries are skipped and single IPs are normalized to /32 or /128 CIDRs.
	srcCSV := strings.NewReader("Network Segment\n10.0.0.0/24\nnot-an-ip\n2001:db8::1\n")

	srcs, err := parseSrcFile(srcCSV)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(srcs) != 2 {
		t.Fatalf("expected 2 valid source entries, got %d", len(srcs))
	}

	if ones, bits := srcs[1].Mask.Size(); ones != bits {
		t.Fatalf("expected single IP to be /128, got /%d", ones)
	}
}

func TestParseDstFileHandlesMetadataAndSingleIP(t *testing.T) {
	// This test validates that destination metadata keys are normalized and single IPs are handled.
	dstCSV := strings.NewReader("Network Segment,Site,Region\n192.168.1.1,DC1,US\n")

	dsts, err := parseDstFile(dstCSV)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(dsts) != 1 {
		t.Fatalf("expected 1 destination, got %d", len(dsts))
	}

	meta := dsts[0].Metadata
	if meta["dst_site"] != "DC1" || meta["dst_region"] != "US" {
		t.Fatalf("expected metadata to include site and region, got %#v", meta)
	}
}

func TestParsePortsFileSkipsInvalidLines(t *testing.T) {
	// This test ensures invalid lines are ignored and only valid TCP/UDP ports are parsed.
	portsTXT := strings.NewReader(strings.Join([]string{
		"ssh,22/tcp",
		"53/udp",
		"invalid",
		"bad/icmp",
		"",
	}, "\n"))

	ports, err := parsePortsFile(portsTXT)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("expected 2 valid port entries, got %d", len(ports))
	}

	if ports[0].Port != 22 || ports[0].Protocol != model.TCP {
		t.Fatalf("expected first port to be 22/tcp, got %d/%s", ports[0].Port, ports[0].Protocol)
	}
	if ports[1].Port != 53 || ports[1].Protocol != model.UDP {
		t.Fatalf("expected second port to be 53/udp, got %d/%s", ports[1].Port, ports[1].Protocol)
	}
}

func TestParseSrcFileErrorsOnMissingHeader(t *testing.T) {
	// This test confirms an explicit error is returned when required headers are missing.
	_, err := parseSrcFile(strings.NewReader("Wrong Header\n10.0.0.0/24\n"))
	if err == nil {
		t.Fatalf("expected error when missing Network Segment header")
	}
}
