-- case01_basic_no_addrgrp: firewall_mgmt schema + inserts
CREATE DATABASE IF NOT EXISTS firewall_mgmt;
USE firewall_mgmt;

DROP TABLE IF EXISTS cfg_policy;
DROP TABLE IF EXISTS cfg_address;
DROP TABLE IF EXISTS cfg_address_group;
DROP TABLE IF EXISTS cfg_service_group;

CREATE TABLE cfg_address (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  fab_name VARCHAR(64) NULL,
  firewall_id VARCHAR(64) NULL,
  object_name VARCHAR(128) NOT NULL,
  address_type VARCHAR(32) NOT NULL,
  subnet VARCHAR(64) NULL,
  start_ip VARCHAR(64) NULL,
  end_ip VARCHAR(64) NULL,
  created_at TIMESTAMP NULL,
  updated_at TIMESTAMP NULL
);

CREATE TABLE cfg_address_group (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  fab_name VARCHAR(64) NULL,
  firewall_id VARCHAR(64) NULL,
  group_name VARCHAR(128) NOT NULL,
  members LONGTEXT NOT NULL,
  created_at TIMESTAMP NULL,
  updated_at TIMESTAMP NULL
);

CREATE TABLE cfg_service_group (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  fab_name VARCHAR(64) NULL,
  firewall_id VARCHAR(64) NULL,
  group_name VARCHAR(128) NOT NULL,
  members LONGTEXT NOT NULL,
  created_at TIMESTAMP NULL,
  updated_at TIMESTAMP NULL
);

CREATE TABLE cfg_policy (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  fab_name VARCHAR(64) NULL,
  firewall_id VARCHAR(64) NULL,
  priority INT NOT NULL,
  policy_id VARCHAR(128) NOT NULL,
  src_objects LONGTEXT NOT NULL,
  dst_objects LONGTEXT NOT NULL,
  service_object LONGTEXT NOT NULL,
  action VARCHAR(16) NOT NULL,
  is_enabled TINYINT(1) NOT NULL,
  log_traffic TINYINT(1) NULL,
  comments TEXT NULL,
  created_at TIMESTAMP NULL,
  updated_at TIMESTAMP NULL
);

INSERT INTO cfg_address (object_name, address_type, subnet, start_ip, end_ip) VALUES
  ('SRC_NET_10', 'subnet', '192.168.10.0/24', NULL, NULL),
  ('SRC_HOST_20_10', 'subnet', '192.168.20.10/32', NULL, NULL),
  ('WEB_NET', 'subnet', '10.0.0.0/24', NULL, NULL),
  ('DB_HOST', 'subnet', '10.0.1.5/32', NULL, NULL);

-- cfg_address_group is intentionally left empty in this bundle.

INSERT INTO cfg_service_group (group_name, members) VALUES
  ('SG_DB_CUSTOM', '["DNS", "SMTP", "tcp_8001-8004"]');

INSERT INTO cfg_policy (priority, policy_id, src_objects, dst_objects, service_object, action, is_enabled, log_traffic, comments) VALUES
  (1, 'P-1', '["SRC_HOST_20_10"]', '["DB_HOST"]', '["SG_DB_CUSTOM"]', 'accept', 1, 0, 'allow db custom tcp range'),
  (2, 'P-2', '["all"]', '["DB_HOST"]', '["ALL"]', 'deny', 1, 1, 'deny all to db'),
  (3, 'P-3', '["SRC_NET_10"]', '["WEB_NET"]', '["HTTP"]', 'accept', 1, 1, 'allow web http from net'),
  (4, 'P-4', '["SRC_HOST_20_10"]', '["WEB_NET"]', '["HTTP"]', 'accept', 1, 1, 'allow web http from host');
