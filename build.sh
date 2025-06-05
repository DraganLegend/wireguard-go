#!/usr/bin/env bash
# Simple one-click build script for wireguard-go
set -e

# Ensure dependencies are up to date
if ! go list -m filippo.io/mlkem768 >/dev/null 2>&1; then
    echo "Fetching quantum resistant dependency filippo.io/mlkem768..."
    go get filippo.io/mlkem768@latest
    go get gvisor.dev/gvisor/runsc@go
fi

# Build the binary using the Makefile
make

echo "Build finished: ./wireguard-go"
