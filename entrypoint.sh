#!/bin/bash
# Entrypoint script to handle monitor/block mode switching

set -e

# Default to block mode if not specified
PROXY_MODE="${PROXY_MODE:-block}"
DCR_STREAM_NAME="${DCR_STREAM_NAME:-Custom-OutboundConnectivityLogs}"

echo "Starting Squid SNI Whitelist Container"
echo "Mode: ${PROXY_MODE}"

# Verify SSL certificates exist
if [ ! -f "/etc/squid/cert.pem" ] || [ ! -f "/etc/squid/key.pem" ]; then
    echo "SSL certificates not found. Generating self-signed certificates..."
    openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
        -subj "/C=US/ST=State/L=City/O=Org/CN=squid-filter" \
        -keyout /etc/squid/key.pem -out /etc/squid/cert.pem
    chmod 600 /etc/squid/key.pem
    echo "SSL certificates generated successfully."
fi

# Initialize SSL certificate database
if [ ! -d "/var/cache/squid/ssl_db" ]; then
    echo "Initializing SSL certificate database..."
    /usr/lib/squid/security_file_certgen -c -s /var/cache/squid/ssl_db -M 4MB
    chown -R squid:squid /var/cache/squid/ssl_db
    echo "SSL certificate database initialized."
fi

# Validate Azure configuration
if [ -z "$DCE_ENDPOINT" ]; then
    echo "ERROR: DCE_ENDPOINT environment variable not set"
    exit 1
fi

if [ -z "$DCR_IMMUTABLE_ID" ]; then
    echo "ERROR: DCR_IMMUTABLE_ID environment variable not set"
    exit 1
fi

echo "Azure Log Analytics configured:"
echo "  DCE Endpoint: ${DCE_ENDPOINT}"
echo "  DCR ID: ${DCR_IMMUTABLE_ID}"
echo "  Stream: ${DCR_STREAM_NAME}"
echo "  Auth: Using VM's system-assigned managed identity"

# Validate whitelist file exists
if [ ! -f "/etc/squid/allowed_domains.txt" ]; then
    echo "WARNING: Whitelist file /etc/squid/allowed_domains.txt not found!"
    echo "Creating default whitelist file..."
    cat > /etc/squid/allowed_domains.txt << 'EOF'
# Squid SNI Whitelist - Default Configuration
# This file was auto-generated because no whitelist was mounted
# Mount your own whitelist file to /etc/squid/allowed_domains.txt
# 
# Format: one domain per line
# Wildcards: .example.com matches all subdomains of example.com
# Comments: lines starting with # are ignored

# Essential Azure services (remove if not needed)
.microsoft.com
.azure.com
.windowsupdate.com

# Add your domains below:

EOF
    echo "Created default whitelist with essential domains"
fi

# Check if the file is empty or only has comments
if [ -f "/etc/squid/allowed_domains.txt" ]; then
    DOMAIN_COUNT=$(grep -v '^#' /etc/squid/allowed_domains.txt | grep -v '^[[:space:]]*$' | wc -l)
    echo "Whitelist contains $DOMAIN_COUNT domains"
    if [ "$DOMAIN_COUNT" -eq 0 ] && [ "$PROXY_MODE" = "block" ]; then
        echo "ERROR: Whitelist is empty and proxy is in BLOCK mode!"
        echo "This will block ALL traffic. Please add domains to the whitelist."
        echo "To run in monitor mode instead, set PROXY_MODE=monitor"
        exit 1
    fi
fi

# Copy the appropriate config file
if [ "$PROXY_MODE" = "monitor" ]; then
    echo "Using monitor mode configuration (all traffic allowed and logged)"
    cp /etc/squid/squid-monitor.conf /etc/squid/squid.conf
else
    echo "Using block mode configuration (whitelist enforced)"
    cp /etc/squid/squid-block.conf /etc/squid/squid.conf
fi

# Validate Squid configuration
echo "Validating Squid configuration..."
if ! squid -k parse; then
    echo "ERROR: Squid configuration validation failed!"
    exit 1
fi

# Initialize Squid cache directories
echo "Initializing Squid cache..."
squid -z -f /etc/squid/squid.conf

# Export DCR_STREAM_NAME for supervisord
export DCR_STREAM_NAME

# Start supervisord
echo "Starting services..."
exec /usr/bin/supervisord -c /etc/supervisord.conf -n