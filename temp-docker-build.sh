#!/bin/bash

# Clean Docker Build Script for syncstorage-rs
# This script performs a complete clean build of the Docker images

set -e

echo "🧹 Starting clean Docker build process..."

# Clean up any existing containers and images
echo "🗑️  Cleaning up existing Docker resources..."
docker system prune -af || true
docker volume prune -f || true

# Remove any existing build artifacts
echo "🗑️  Removing build artifacts..."
rm -rf target/
rm -rf .cargo/

# Build the main application image
echo "🔨 Building syncstorage-rs Docker image..."
docker build -t syncstorage-rs:latest .

# Build the keycloak-enabled image
echo "🔨 Building Keycloak-enabled image..."
docker build -f docker/Dockerfile.keycloak -t app:keycloak .

# Build the minimal image
echo "🔨 Building minimal image..."
docker build -f docker/Dockerfile.minimal -t app:minimal .

# Verify images were built successfully
echo "✅ Verifying built images..."
docker images | grep -E "(syncstorage-rs|app)"

echo "🎉 Docker build process completed successfully!"
echo ""
echo "Available images:"
echo "  - syncstorage-rs:latest (main application)"
echo "  - app:keycloak (Keycloak-enabled)"
echo "  - app:minimal (minimal build)"
echo ""
echo "You can now run the e2e tests with:"
echo "  make docker_run_mysql_keycloak_e2e_tests"
echo "  make docker_run_mysql_e2e_tests"