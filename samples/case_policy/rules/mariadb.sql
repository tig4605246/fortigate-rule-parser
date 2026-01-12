-- firewall_mgmt schema + inserts
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
  ('SRC_NET', 'subnet', '10.40.0.0/24', NULL, NULL),
  ('DST_NET', 'subnet', '172.40.0.0/24', NULL, NULL);

INSERT INTO cfg_address_group (group_name, members) VALUES
  ('AG_SRC', '["SRC_NET"]'),
  ('AG_DST', '["DST_NET"]');

INSERT INTO cfg_service_group (group_name, members) VALUES
  ('SG_MAIN', '["DNS", "SMTP", "tcp_8080", "udp_53", "tcp_3000-3002", "udp_4000-4001"]'),
  ('SG_EXTRA', '["tcp_1000-1002", "tcp_8443", "udp_2000-2001", "udp_5353", "TCP", "SMTP", "POP3", "DNS", "DCE-RPC", "SAMBA"]');

INSERT INTO cfg_policy (priority, policy_id, src_objects, dst_objects, service_object, action, is_enabled, log_traffic, comments) VALUES
  (1, '1', '["SRC_NET"]', '["DST_NET"]', '["ALL"]', 'deny', 0, 0, 'disabled deny'),
  (2, '2', '["SRC_NET"]', '["DST_NET"]', '["HTTP"]', 'deny', 1, 1, 'deny http'),
  (3, '3', '["SRC_NET"]', '["DST_NET"]', '["SSH"]', 'accept', 1, 1, 'allow ssh');
