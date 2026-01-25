Summary of Key Differences
The Go version was written to prioritize performance and concurrency, which led to several key design differences compared to the more flexible Python version.

1. Parsing Firewall Rules
Difference: FQDN Object Handling
Python: The Python parser and evaluator have a concept of an UNKNOWN match outcome. When a policy uses a Firewall Address Object of type FQDN (e.g., www.example.com), the evaluator cannot statically know what IP it resolves to. The Python version flags this situation as UNKNOWN, allowing the user to know that the result is indeterminate.
Go: The Go implementation prioritizes deterministic, high-speed analysis. When the Go parser encounters an FQDN address object, it is parsed correctly, but the evaluator currently treats it as a non-match because no static IP can be confirmed. It does not have a third UNKNOWN state; a flow is either ALLOW or DENY.
Example Case of Different Results:
rules/fortigate.conf:

config firewall address
    edit "ExternalService"
        set type fqdn
        set fqdn "api.partner.com"
    next
end
config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "ExternalService"
        set service "HTTPS"
        set action accept
    next
end
inputs/src.csv: Contains an internal IP, e.g., 192.168.1.10/32.

inputs/dst.csv: Contains a dummy destination, e.g., 8.8.8.8/32. (Note: The destination IP is irrelevant as the policy matches on the FQDN object).

Python Result: For traffic from 192.168.1.10 to any destination on port 443, the result would be UNKNOWN because the ExternalService object cannot be statically resolved.

Go Result: The same traffic would result in a DENY (specifically, IMPLICIT_DENY), because the ExternalService FQDN object is skipped during evaluation, causing Policy 1 to not match.

2. Parsing Inputs (implemented)
Difference: CIDR Block Expansion
Python: The Python implementation is capable of fully expanding CIDR blocks from the input files (src.csv, dst.csv). In its expand mode, if src.csv contains 10.0.0.0/30, it will generate and test four distinct source IPs (10.0.0.0, 10.0.0.1, 10.0.0.2, 10.0.0.3).
Go: To achieve maximum performance and avoid iterating over potentially millions of IPs, the Go implementation's producer goroutine simplifies this. For any given CIDR in the input files, it generates only one task using the network address (the first IP) of the block as a representative sample.
Example Case of Different Results:
inputs/src.csv:

Network Segment
172.16.0.0/24
rules/fortigate.conf:

config firewall address
    edit "AllowedServer"
        set type ipmask
        set subnet 172.16.0.55 255.255.255.255
    next
end
config firewall policy
    edit 1
        set srcaddr "AllowedServer"
        set dstaddr "all"
        set service "all"
        set action accept
    next
end
Python Result: When running in expand mode, the Python tool would test all 256 IPs in the 172.16.0.0/24 range. It would produce 255 DENY results and one ALLOW result for the source IP 172.16.0.55.

Go Result: The Go tool would only test the IP 172.16.0.0. Since this IP does not match the "AllowedServer" object, it would check no further and produce a single DENY result for the entire 172.16.0.0/24 network segment, completely missing the allowed flow.

3. Policy Simulation
Difference: "Fuzzy" Network Overlap vs. Point-in-CIDR Check
Python: The Python evaluator has a "fuzzy" matching mode. In this mode, a match occurs if the input network (from src.csv/dst.csv) and the address object network in the policy have any overlap at all.
Go: The Go evaluator, due to its single-IP sampling strategy, performs a simple "point-in-CIDR" check. It only tests if the single representative IP from the input network is contained within the policy's address object network.
Example Case of Different Results:
inputs/src.csv:
Network Segment
10.0.0.0/24
rules/fortigate.conf:
config firewall address
    edit "SecondHalf"
        set type ipmask
        set subnet 10.0.0.128 255.255.255.128  # This is 10.0.0.128/25
    next
end
config firewall policy
    edit 1
        set srcaddr "SecondHalf"
        set dstaddr "all"
        set service "all"
        set action accept
    next
end
Python Result: In fuzzy mode, the evaluator would detect that the input network 10.0.0.0/24 and the policy's network 10.0.0.128/25 overlap. It would therefore register a MATCH, and the final decision would be ALLOW.
Go Result: The Go evaluator tests only the representative IP 10.0.0.0. Since 10.0.0.0 is not contained within the 10.0.0.128/25 network, the source address check fails (svc_match: false). The policy does not match, and the result is an IMPLICIT_DENY.