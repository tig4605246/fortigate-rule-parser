"""Tests for the database parser."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from static_traffic_analyzer.parsers.db import parse_database


def test_parse_database_buffered():
    """Verify that the database parser correctly processes data with buffered reads."""
    address_data = [
        {
            "object_name": "net1",
            "address_type": "ipmask",
            "subnet": "192.168.1.0/24",
            "start_ip": None,
            "end_ip": None,
        }
    ]
    address_group_data = [{"group_name": "agrp1", "members": '["net1"]'}]
    service_group_data = [{"group_name": "sgrp1", "members": '["tcp_80"]'}]
    policy_data = [
        {
            "priority": 1,
            "policy_id": "1",
            "src_objects": '["agrp1"]',
                            "dst_objects": '["any"]',
                            "service_objects": '["sgrp1"]',
                            "action": "accept",            "is_enabled": 1,
            "log_traffic": 0,
            "comments": "Test policy",
        }
    ]
    mock_cursor = MagicMock()
    mock_cursor.__enter__.return_value = mock_cursor

    # This is the crucial part for testing the buffered read.
    # The mock cursor needs to be iterable.
    def execute_effect(query, params=None):
        if "cfg_address_group" in query:
            mock_cursor.__iter__.return_value = iter(address_group_data)
        elif "cfg_address" in query:
            mock_cursor.__iter__.return_value = iter(address_data)
        elif "cfg_service_group" in query:
            mock_cursor.__iter__.return_value = iter(service_group_data)
        elif "cfg_policy" in query:
            mock_cursor.__iter__.return_value = iter(policy_data)
    mock_cursor.execute.side_effect = execute_effect

    mock_connection = MagicMock()
    mock_connection.cursor.return_value = mock_cursor

    with patch("mysql.connector.connect", return_value=mock_connection) as mock_connect:
        db_data = parse_database("user", "password", "host", "db")

        # Assert that the connector was called
        mock_connect.assert_called_once_with(user="user", password="password", host="host", database="db")

        # Assert parsing results
        assert "net1" in db_data.address_book.objects
        assert "agrp1" in db_data.address_book.groups
        assert db_data.address_book.groups["agrp1"].members == ("net1",)

        assert "sgrp1" in db_data.service_book.groups
        assert db_data.service_book.groups["sgrp1"].members == ("tcp_80",)

        assert len(db_data.policies) == 1
        policy = db_data.policies[0]
        assert policy.policy_id == "1"
        assert policy.source == ("agrp1",)
        assert policy.destination == ("any",)
        assert policy.services == ("sgrp1",)
        assert policy.action == "accept"
        assert policy.enabled is True

        # Check that fetchall was not called
        assert mock_cursor.fetchall.call_count == 0
        assert policy.enabled is True

        # Check that fetchall was not called
        assert mock_cursor.fetchall.call_count == 0
