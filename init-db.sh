#!/bin/bash
set -e

echo "Creating test database..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    SELECT 'CREATE DATABASE fastapi_test_db'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'fastapi_test_db')\gexec
EOSQL

echo "Test database created successfully!"
