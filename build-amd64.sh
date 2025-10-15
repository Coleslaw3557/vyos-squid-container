#!/bin/bash
# Build script for amd64 architecture
# Ensures container is built for VyOS x86_64 platform

set -e

echo "Building squid-whitelist container for amd64 platform..."

# Detect available container build tool
if command -v docker &> /dev/null; then
    BUILD_CMD="docker"
elif command -v podman &> /dev/null; then
    BUILD_CMD="podman"
else
    echo "Error: Neither docker nor podman found"
    exit 1
fi

echo "Using $BUILD_CMD for building..."

# Build the container
if [[ "$BUILD_CMD" == "docker" ]]; then
    docker build --platform linux/amd64 -t squid-whitelist:latest .
elif [[ "$BUILD_CMD" == "podman" ]]; then
    # Check if podman supports --platform flag
    if podman build --help | grep -q -- --platform; then
        podman build --platform linux/amd64 -t squid-whitelist:latest .
    else
        echo "Warning: podman may not support --platform flag"
        echo "Attempting build with TARGETARCH env variable"
        TARGETARCH=amd64 podman build -t squid-whitelist:latest .
    fi
fi

# Verify the build
echo "Verifying container architecture..."
ARCH=$($BUILD_CMD inspect squid-whitelist:latest --format='{{.Architecture}}')

if [[ "$ARCH" == "amd64" ]] || [[ "$ARCH" == "x86_64" ]]; then
    echo "[OK] Successfully built for $ARCH architecture"
    echo "  Platform: $($BUILD_CMD inspect squid-whitelist:latest --format='{{.Os}}/{{.Architecture}}')"
else
    echo "[WARNING] Container built for $ARCH architecture, expected amd64"
    echo "  You may need to:"
    echo "  1. Ensure Docker Desktop is set to use linux/amd64 platform"
    echo "  2. Use: docker buildx build --platform linux/amd64 -t squid-whitelist:latest ."
    echo "  3. Build on an actual amd64/x86_64 machine"
fi

echo ""
echo "Exporting container to squid-whitelist.tar..."
$BUILD_CMD save squid-whitelist:latest -o squid-whitelist.tar

# Show file info
if [[ -f squid-whitelist.tar ]]; then
    FILE_SIZE=$(ls -lh squid-whitelist.tar | awk '{print $5}')
    echo "[OK] Container exported successfully"
    echo "  File: squid-whitelist.tar ($FILE_SIZE)"
    echo ""
    echo "To transfer to VyOS:"
    echo "  scp squid-whitelist.tar vyos@<vyos-ip>:/tmp/"
    echo ""
    echo "To load on VyOS:"
    echo "  sudo podman load -i /tmp/squid-whitelist.tar"
else
    echo "[ERROR] Failed to export container"
    exit 1
fi