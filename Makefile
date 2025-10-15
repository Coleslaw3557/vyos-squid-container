# Makefile for VyOS Squid SNI Whitelist Container

.PHONY: build build-amd64 save clean test-monitor test-block help

# Default target
help:
	@echo "VyOS Squid Container Build Targets:"
	@echo "  make build       - Build container for current platform"
	@echo "  make build-amd64 - Build container for amd64 (VyOS)"
	@echo "  make save        - Export container to tar file"
	@echo "  make clean       - Remove built images"
	@echo "  make test-monitor - Test run in monitor mode"
	@echo "  make test-block  - Test run in block mode"

# Build for current platform
build:
	podman build -t squid-whitelist:latest .

# Build specifically for amd64 (VyOS architecture)
build-amd64:
	@echo "Building for linux/amd64 platform..."
	podman build --platform linux/amd64 -t squid-whitelist:latest .
	@echo "Verifying architecture..."
	@podman inspect squid-whitelist:latest | grep '"Architecture"' || true

# Export container for transfer to VyOS
save:
	podman save squid-whitelist:latest -o squid-whitelist.tar
	@echo "Container saved to squid-whitelist.tar"
	@ls -lh squid-whitelist.tar

# Clean up images
clean:
	podman rmi squid-whitelist:latest || true
	rm -f squid-whitelist.tar

# Test run in monitor mode
test-monitor:
	@echo "Creating test whitelist file..."
	@echo ".example.com" > test-allowed_domains.txt
	@echo ".microsoft.com" >> test-allowed_domains.txt
	podman run --rm \
		--platform linux/amd64 \
		-v ./test-allowed_domains.txt:/etc/squid/allowed_domains.txt:ro \
		-e DCE_ENDPOINT=https://example.datacollection.azure.com \
		-e DCR_IMMUTABLE_ID=dcr-test \
		-e PROXY_MODE=monitor \
		-p 3129:3129 -p 3130:3130 \
		squid-whitelist:latest

# Test run in block mode
test-block:
	@echo "Creating test whitelist file..."
	@echo ".example.com" > test-allowed_domains.txt
	@echo ".microsoft.com" >> test-allowed_domains.txt
	podman run --rm \
		--platform linux/amd64 \
		-v ./test-allowed_domains.txt:/etc/squid/allowed_domains.txt:ro \
		-e DCE_ENDPOINT=https://example.datacollection.azure.com \
		-e DCR_IMMUTABLE_ID=dcr-test \
		-e PROXY_MODE=block \
		-p 3129:3129 -p 3130:3130 \
		squid-whitelist:latest