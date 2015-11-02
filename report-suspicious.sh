#!/bin/bash
./list-connections.py $1 --suspicious --date-from 7d -o tsv | cut -d'	' -f 1-5 | sort | uniq > report.csv
