package parser

import (
	"strings"
	"testing"

	"static-traffic-analyzer/internal/model"
)

func TestParseInputTrafficParsesAllInputs(t *testing.T) {
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
}

func TestParseSrcFileHandlesInvalidAndSingleIPEntries(t *testing.T) {
	srcCSV := strings.NewReader("Network Segment\n10.0.0.0/24\nnot-an-ip\n2001:db8::1\n1.1.1.1\n")

	srcs, err := parseSrcFile(srcCSV)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(srcs) != 3 {
		t.Fatalf("expected 3 valid source entries, got %d", len(srcs))
	}

	// 2001:db8::1 should be /128
	if ones, bits := srcs[1].Mask.Size(); ones != 128 || bits != 128 {
		t.Fatalf("expected IPv6 single IP to be /128, got /%d", ones)
	}
	// 1.1.1.1 should be /32
	if ones, bits := srcs[2].Mask.Size(); ones != 32 || bits != 32 {
		t.Fatalf("expected IPv4 single IP to be /32, got /%d", ones)
	}
}

func TestParseDstFileHandlesMetadataAndSingleIP(t *testing.T) {
	dstCSV := strings.NewReader("Network Segment,Site,Region\n192.168.1.1,DC1,US\n10.0.0.1,DC2,EU\n")

	dsts, err := parseDstFile(dstCSV)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(dsts) != 2 {
		t.Fatalf("expected 2 destinations, got %d", len(dsts))
	}

	meta := dsts[0].Metadata
	if meta["dst_site"] != "DC1" || meta["dst_region"] != "US" {
		t.Fatalf("expected metadata to include site and region, got %#v", meta)
	}
}

func TestParsePortsFileSkipsInvalidLines(t *testing.T) {
	portsTXT := strings.NewReader(strings.Join([]string{
		"ssh,22/tcp",
		"53/udp",
		"http,80",
		"invalid",
		"bad/icmp",
		"notaport/tcp",
		"80/tcp",
		"",
	}, "\n"))

	ports, err := parsePortsFile(portsTXT)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 valid port entries, got %d", len(ports))
	}
}

func TestParseSrcFileErrorsOnMissingHeader(t *testing.T) {
	_, err := parseSrcFile(strings.NewReader("Wrong Header\n10.0.0.0/24\n"))
	if err == nil {
		t.Fatalf("expected error when missing Network Segment header")
	}
	
	_, err = parseSrcFile(strings.NewReader(""))
	if err == nil {
		t.Fatalf("expected error when file is empty")
	}
}

func TestParseDstFileErrorsOnMissingHeader(t *testing.T) {
	_, err := parseDstFile(strings.NewReader("Wrong Header\n10.0.0.0/24\n"))
	if err == nil {
		t.Fatalf("expected error when missing Network Segment header")
	}

	_, err = parseDstFile(strings.NewReader(""))
	if err == nil {
		t.Fatalf("expected error when file is empty")
	}
}
