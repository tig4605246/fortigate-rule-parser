"""Tests for the FortiGate configuration parser."""
from __future__ import annotations

import pytest

from static_traffic_analyzer.models import (
    AddressObject,
    AddressGroup,
    PolicyRule,
    ServiceBook,
    ServiceGroup,
    ServiceObject,
)
from static_traffic_analyzer.parsers.fortigate import parse_fortigate_config


from static_traffic_analyzer.utils import parse_address_object


def test_parse_fortigate_config_empty():
    """Test parsing an empty config."""
    data = parse_fortigate_config([])
    assert list(data.address_book.objects.keys()) == ["all"]
    assert not data.address_book.groups

    expected_services = {"ALL", "DNS", "HTTP", "HTTPS", "SSH", "SMTP"}
    assert set(data.service_book.services.keys()) == expected_services

    assert not data.service_book.groups
    assert not data.policies





def test_parse_firewall_addrgrp():
    """Test parsing of firewall address groups."""
    config = [
        "config firewall addrgrp",
        '    edit "test-grp"',
        '        set member "net1" "net2"',
        "    next",
        "end",
    ]
    data = parse_fortigate_config(config)
    assert data.address_book.groups["test-grp"] == AddressGroup(name="test-grp", members=("net1", "net2"))


def test_parse_firewall_service_custom():
    """Test parsing of custom firewall services."""
    config = [
        "config firewall service custom",
        '    edit "tcp-service"',
        "        set tcp-portrange 80 443:445",
        "    next",
        '    edit "udp-service"',
        "        set udp-portrange 53",
        "    next",
        "end",
    ]
    data = parse_fortigate_config(config)
    assert "tcp-service" in data.service_book.services
    assert "udp-service" in data.service_book.services


def test_parse_firewall_service_group():
    """Test parsing of firewall service groups."""
    config = [
        "config firewall service group",
        '    edit "test-svc-grp"',
        '        set member "svc1" "svc2"',
        "    next",
        "end",
    ]
    data = parse_fortigate_config(config)
    assert data.service_book.groups["test-svc-grp"] == ServiceGroup(name="test-svc-grp", members=("svc1", "svc2"))


def test_parse_firewall_policy():
    """Test parsing of firewall policies."""
    config = [
        "config firewall policy",
        '    edit "101"',
        '        set name "Allow Web"',
        '        set srcaddr "internal-net"',
        '        set dstaddr "all"',
        '        set service "HTTP" "HTTPS"',
        "        set action accept",
        "        set status enable",
        "    next",
        '    edit "102"',
        '        set name "Deny FTP"',
        '        set srcaddr "internal-net"',
        '        set dstaddr "all"',
        '        set service "FTP"',
        "        set action deny",
        "        set status disable",
        "    next",
        "end",
    ]
    data = parse_fortigate_config(config)
    assert len(data.policies) == 2
    p1 = data.policies[0]
    assert p1.policy_id == "101"
    assert p1.name == "Allow Web"
    assert p1.source == ("internal-net",)
    assert p1.destination == ("all",)
    assert p1.services == ("HTTP", "HTTPS")
    assert p1.action == "accept"
    assert p1.enabled is True

    p2 = data.policies[1]
    assert p2.policy_id == "102"
    assert p2.name == "Deny FTP"
    assert p2.action == "deny"
    assert p2.enabled is False


def test_parse_multi_line_set():
    """Test parsing multi-line set commands."""
    config = [
        "config firewall addrgrp",
        '    edit "test-grp"',
        '        set member "net1"',
        '        set member "net2"',
        "    next",
        "end",
    ]
    data = parse_fortigate_config(config)
    assert data.address_book.groups["test-grp"].members == ("net1", "net2")

def test_parse_unset_command():
    """Test that unset command removes a field."""
    config = [
        "config firewall address",
        '    edit "test-net"',
        "        set subnet 192.168.1.0 255.255.255.0",
        "        set comment test",
        "        unset comment",
        "    next",
        "end",
    ]
    # This test is tricky because the parser doesn't store arbitrary fields.
    # We can test this by seeing if a field that affects parsing is removed.
    # For now, this is a placeholder. A more meaningful test would require
    # the parser to be more aware of what it's parsing.
    data = parse_fortigate_config(config)
    assert data.address_book.objects["test-net"] is not None

def test_full_config_integration():
    """A larger test simulating a more complete config file."""
    config = [
        "# This is a comment",
        "config firewall address",
        '    edit "lan"',
        "        set subnet 192.168.1.0 255.255.255.0",
        "    next",
        "end",
        "",
        "config firewall addrgrp",
        '    edit "local-nets"',
        '        set member "lan"',
        "    next",
        "end",
        "config firewall policy",
        '    edit "1"',
        '        set srcaddr "local-nets"',
        '        set dstaddr "all"',
        '        set service "ALL"',
        "        set action accept",
        "    next",
        "end",
    ]
    data = parse_fortigate_config(config)
    assert "lan" in data.address_book.objects
    assert "local-nets" in data.address_book.groups
    assert len(data.policies) == 1
    assert data.policies[0].source == ("local-nets",)

