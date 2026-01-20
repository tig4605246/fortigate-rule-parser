-- MariaDB schema (as provided)
CREATE DATABASE IF NOT EXISTS firewall_mgmt;
USE firewall_mgmt;

DROP TABLE IF EXISTS cfg_policy;
DROP TABLE IF EXISTS cfg_address;
DROP TABLE IF EXISTS cfg_address_group;
DROP TABLE IF EXISTS cfg_service_group;

CREATE TABLE cfg_address (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  fab_name VARCHAR(16) NULL,
  firewall_id VARCHAR(64) NULL,
  object_name VARCHAR(64) NOT NULL,
  address_type VARCHAR(16) NOT NULL,
  subnet VARCHAR(64) NULL,
  start_ip VARCHAR(64) NULL,
  end_ip VARCHAR(64) NULL,
  created_at TIMESTAMP NULL,
  updated_at TIMESTAMP NULL
);

CREATE TABLE cfg_address_group (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  fab_name VARCHAR(16) NULL,
  firewall_id VARCHAR(64) NULL,
  group_name VARCHAR(64) NOT NULL,
  members LONGTEXT NOT NULL,
  created_at TIMESTAMP NULL,
  updated_at TIMESTAMP NULL
);

CREATE TABLE cfg_service_group (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  fab_name VARCHAR(16) NULL,
  firewall_id VARCHAR(64) NULL,
  group_name VARCHAR(64) NOT NULL,
  members LONGTEXT NOT NULL,
  created_at TIMESTAMP NULL,
  updated_at TIMESTAMP NULL
);

CREATE TABLE cfg_policy (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  fab_name VARCHAR(16) NULL,
  firewall_id VARCHAR(64) NULL,
  priority INT(10) UNSIGNED NOT NULL,
  policy_id INT(10) UNSIGNED NOT NULL,
  src_objects LONGTEXT NOT NULL,
  dst_objects LONGTEXT NOT NULL,
  service_objects LONGTEXT NOT NULL,
  action VARCHAR(16) NOT NULL,
  is_enabled VARCHAR(16) NOT NULL,
  log_traffic VARCHAR(16) NULL,
  comments VARCHAR(1024) NULL,
  created_at TIMESTAMP NULL,
  updated_at TIMESTAMP NULL
);
INSERT INTO cfg_address (fab_name, firewall_id, object_name, address_type, subnet) VALUES
  ('FAB', 'FW1', 'SRC_NET_10', 'ipmask', '192.168.10.0/24'),
  ('FAB', 'FW1', 'DST_WEB_NET', 'ipmask', '10.0.0.0/24');

INSERT INTO cfg_policy (fab_name, firewall_id, priority, policy_id, src_objects, dst_objects, service_objects, action, is_enabled, log_traffic, comments)
VALUES
  ('FAB', 'FW1', 30, 30, '["SRC_NET_10"]', '["DST_WEB_NET"]', '["ALL"]', 'deny', 'enable', 'all', 'deny all (shadow test)'),
  ('FAB', 'FW1', 31, 31, '["SRC_NET_10"]', '["DST_WEB_NET"]', '["HTTP"]', 'accept', 'enable', 'all', 'allow http (should not match)');
