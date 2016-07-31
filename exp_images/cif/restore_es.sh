#!/bin/bash

curl -XPUT 'http://localhost:9200/_snapshot/asgard_backup' -d '{
    "type": "fs",
    "settings": {
        "compress" : true,
        "location": "/es_backup"
    }
}'

curl -XPOST 'localhost:9200/cif.tokens/_close'

curl -XPOST 'http://localhost:9200/_snapshot/asgard_backup/snapshot_1/_restore'
