-- case03_fqdn_no_addrgrp: minimal schema + inserts
CREATE DATABASE IF NOT EXISTS firewall_mgmt;
USE firewall_mgmt;

DROP TABLE IF EXISTS cfg_policy;
DROP TABLE IF EXISTS cfg_address;
DROP TABLE IF EXISTS cfg_address_group;
DROP TABLE IF EXISTS cfg_service_group;

CREATE TABLE cfg_address (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  object_name VARCHAR(128) NOT NULL,
  address_type VARCHAR(32) NOT NULL,
  subnet VARCHAR(256) NULL,
  start_ip VARCHAR(64) NULL,
  end_ip VARCHAR(64) NULL
);

CREATE TABLE cfg_address_group (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  group_name VARCHAR(128) NOT NULL,
  members LONGTEXT NOT NULL
);

CREATE TABLE cfg_service_group (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  group_name VARCHAR(128) NOT NULL,
  members LONGTEXT NOT NULL
);

CREATE TABLE cfg_policy (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  priority INT NOT NULL,
  policy_id VARCHAR(128) NOT NULL,
  src_objects LONGTEXT NOT NULL,
  dst_objects LONGTEXT NOT NULL,
  service_object LONGTEXT NOT NULL,
  action VARCHAR(16) NOT NULL,
  is_enabled TINYINT(1) NOT NULL,
  comments TEXT NULL
);

INSERT INTO cfg_address (object_name, address_type, subnet) VALUES
  ('SRC_NET_10', 'subnet', '192.168.10.0/24'),
  ('WEB_FQDN', 'fqdn', 'example.com');

INSERT INTO cfg_policy (priority, policy_id, src_objects, dst_objects, service_object, action, is_enabled, comments) VALUES
  (1, 'P-1', '["SRC_NET_10"]', '["WEB_FQDN"]', '["HTTP"]', 'accept', 1, 'allow http to fqdn');
