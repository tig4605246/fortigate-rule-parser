#!/bin/bash
# Script to run all Go unit tests in the repository.

# Ensure we're in the project root
PROJECT_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$PROJECT_ROOT"

echo "Running Go unit tests..."
go test -v -race -cover ./...
