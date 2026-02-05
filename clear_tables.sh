#!/bin/bash

# Configuration
DB_NAME="klarto_db"
DB_USER="klarto_api_user"

echo "--- Clearing all tables in $DB_NAME ---"

# 1. Terminate active connections to avoid lock errors
echo "Terminating active connections..."
sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$DB_NAME' AND pid <> pg_backend_pid();"

# 2. Drop and Recreate the public schema (wipes all tables, triggers, and types)
echo "Dropping all tables..."
sudo -u postgres psql -d $DB_NAME -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

# 3. Restore permissions for your API user
echo "Restoring permissions..."
sudo -u postgres psql -d $DB_NAME -c "GRANT ALL ON SCHEMA public TO $DB_USER; GRANT ALL ON SCHEMA public TO public;"

echo "--- Success: All tables cleared ---"
