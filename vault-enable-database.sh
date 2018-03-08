#!/bin/bash

# This script demonstrates how to setup Vault to be able to run the example code in main.go.

set -euo pipefail

vault secrets enable database

vault write database/config/my-mysql-database \
    plugin_name=mysql-database-plugin \
    connection_url="root:@tcp(127.0.0.1:3306)/" \
    allowed_roles="my-role"

vault write database/roles/my-role \
    db_name=my-mysql-database \
    creation_statements="GRANT ALL ON *.* TO '{{name}}'@'localhost' IDENTIFIED BY '{{password}}';" \
    default_ttl="10m" \
    max_ttl="24h"
