#!/bin/bash
set -e

echo "Building syncserver with keycloak feature enabled..."

# Build the syncserver binary with keycloak feature
cd /workspace/syncstorage-rs
cargo build --release --no-default-features --features=syncstorage-db/mysql,keycloak --bin syncserver

# Copy the binary to the Docker container
docker cp target/release/syncserver syncstorage-rs-syncserver-1:/app/bin/syncserver

echo "Syncserver binary updated with keycloak feature!"