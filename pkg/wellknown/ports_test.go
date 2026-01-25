package wellknown

import (
	"testing"

	"static-traffic-analyzer/internal/model"
)

func TestGetServiceReturnsDNSAliases(t *testing.T) {
	// This test ensures DNS aliases map to the expected port/protocol entries.
	entries, ok := GetService("dns")
	if !ok {
		t.Fatalf("expected dns to be present in well-known service registry")
	}
	if !containsPort(entries, 53, model.TCP) && !containsPort(entries, 53, model.UDP) {
		t.Fatalf("expected DNS to include port 53 over tcp or udp, got %#v", entries)
	}
}

func TestGetServiceIncludesIcmpSentinel(t *testing.T) {
	// This test confirms the ICMP sentinel entry is registered for ignore handling.
	entries, ok := GetService(ICMP)
	if !ok {
		t.Fatalf("expected ICMP sentinel to be present")
	}
	if !containsPort(entries, 65535, model.TCP) {
		t.Fatalf("expected ICMP sentinel to have port 65535/tcp, got %#v", entries)
	}
}

func TestGetServiceReturnsFalseForUnknown(t *testing.T) {
	// This test validates the registry returns false for unknown services.
	_, ok := GetService("definitely-not-a-service")
	if ok {
		t.Fatalf("expected unknown service to return ok=false")
	}
}

func containsPort(entries []ServiceEntry, port int, protocol model.Protocol) bool {
	// Helper keeps entry inspection readable for multiple service assertions.
	for _, entry := range entries {
		if entry.Port == port && entry.Protocol == protocol {
			return true
		}
	}
	return false
}
