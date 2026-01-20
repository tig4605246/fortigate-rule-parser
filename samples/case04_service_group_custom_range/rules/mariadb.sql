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
  ('FAB', 'FW1', 'SRC_HOST_20_10', 'ipmask', '192.168.20.10/32'),
  ('FAB', 'FW1', 'DST_DB_HOST', 'ipmask', '10.0.1.5/32');

INSERT INTO cfg_service_group (fab_name, firewall_id, group_name, members) VALUES
  ('FAB', 'FW1', 'SG_DB_CUSTOM', '["tcp_8001-8004"]');

INSERT INTO cfg_policy (fab_name, firewall_id, priority, policy_id, src_objects, dst_objects, service_objects, action, is_enabled, log_traffic, comments)
VALUES
  ('FAB', 'FW1', 40, 40, '["SRC_HOST_20_10"]', '["DST_DB_HOST"]', '["SG_DB_CUSTOM"]', 'accept', 'enable', 'all', 'allow custom tcp range 8001-8004');
