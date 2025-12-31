# static-traffic-analyzer

## Purpose

The tool is made to parse firewall rules from a designated source and map src/dst ip port pair to see if the route will be allowed to pass or not. Finally output the result to a csv file.

The implementation of the tool can be divided into 3 parts
1. parse rules from either FortiGate configuration, Excel or MariaDB tables
  - `fortigate-rule-parser-conf`
  - `fortigate-rule-parser-excel`
  - `fortigate-rule-parser-mariadb`
2. Verify each src ip, dst ip and port pair is allow to access or not
3. output result as a csv or JSON for port scanner

## Overview

A FrotiGate configuration written in Golang
