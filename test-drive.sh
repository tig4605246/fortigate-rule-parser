#! /bin/bash
PYTHONPATH=src python3 -m static_traffic_analyzer.cli --config samples/case01_basic/rules/fortigate.conf \
  --src-csv samples/case01_basic/inputs/src.csv \
  --dst-csv samples/case01_basic/inputs/dst.csv \
  --ports samples/case01_basic/inputs/ports.txt \
  --out out.csv

diff -u out.csv samples/case01_basic/expected/expected.csv

$ docker run --detach --name some-mariadb --env MARIADB_ROOT_PASSWORD=dummy mariadb:latest
