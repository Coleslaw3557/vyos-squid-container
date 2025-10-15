# VyOS SNI-Based Domain Whitelisting Specification

## Purpose

Block malware command-and-control (C2) communication by implementing a domain whitelist that only allows traffic to approved domains. This prevents malware from phoning home to attacker-controlled infrastructure while allowing legitimate traffic to trusted domains. All connection attempts (allowed and blocked) are logged to Azure Log Analytics for monitoring and threat analysis.

## Approach

Use SNI (Server Name Indication) inspection to filter HTTPS traffic by domain without performing full SSL/TLS decryption. SNI is transmitted in plaintext during the TLS handshake, allowing domain-based filtering without MITM or client certificate installation.

## Architecture

1. **Squid proxy container** - Runs in Podman on VyOS, inspects SNI and enforces domain whitelist
2. **External whitelist file** - Mounted from VyOS host at `/config/squid-whitelist/allowed_domains.txt`, allows dynamic updates without container rebuild
3. **Python log monitor** - Runs inside container, sends all allowed/blocked connection logs to Azure Log Analytics
4. **VyOS NAT** - Redirects all HTTP/HTTPS traffic to the Squid container
5. **VyOS firewall** - Blocks UDP 443 (QUIC/HTTP3) and prevents direct bypass of the proxy
6. **Azure Managed Identity** - VyOS VM uses system-assigned identity for Log Analytics authentication (no credentials in container)

## Technical Details

### Container Configuration

**Squid operates in "splice mode":**
- Peeks at SNI during TLS handshake
- Makes allow/deny decision based on external domain whitelist file
- Splices connection through without decrypting HTTPS traffic
- No client certificates required - not a true MITM

**Whitelist file format:**
- Location on VyOS host: `/config/squid-whitelist/allowed_domains.txt`
- Mounted into container at: `/etc/squid/allowed_domains.txt`
- Format: One domain per line, supports wildcard (`.cisco.com` matches `*.cisco.com`)
- Updates: Reload Squid after modifying file (`podman exec squid-filter squid -k reconfigure`)

**Logging:**
- All connections (allowed and blocked) logged to `/var/log/squid/access.log` inside container
- Python monitor reads logs in real-time and sends to Azure Log Analytics
- Uses Azure Managed Identity for authentication (no secrets in container)

**Ports:**
- 3129: HTTP interception
- 3130: HTTPS interception (SNI inspection)

### Traffic Flow

```
Client → VyOS NAT → Squid Container → Internet
         (redirect)  (SNI check)      (if allowed)
                          ↓
                    Log Monitor → Azure Log Analytics
                    (allowed/blocked events)
```

1. Client attempts connection to any domain
2. VyOS NAT redirects to Squid container
3. Squid inspects SNI field in TLS handshake
4. Squid checks domain against external whitelist file (`/etc/squid/allowed_domains.txt`)
5. If domain matches whitelist: allow and splice through
6. If domain not whitelisted: drop connection
7. Log monitor captures all allow/deny decisions and sends to Azure Log Analytics
8. Allowed traffic passes encrypted to destination

### Security Boundaries

**Blocked:**
- All domains not on whitelist
- UDP 443 (QUIC/HTTP3) - forced fallback to TCP
- Direct connections bypassing proxy

**Allowed:**
- Whitelisted domains only
- HTTP and HTTPS over TCP

## Known Limitations

1. **Encrypted ClientHello (ECH)** - Future TLS extension that encrypts SNI will break this approach (not yet widespread)
2. **HTTP/2 multiplexing** - Not a practical concern for malware C2; requires server cooperation to relay traffic
3. **Non-HTTP protocols** - SSH, custom TCP protocols, DNS tunneling bypass this filtering
4. **Compromised whitelisted domains** - If a whitelisted domain is compromised, malware can use it

## Implementation

### Prerequisites

1. **Azure Resources:**
   - VyOS VM with system-assigned managed identity enabled
   - Log Analytics workspace
   - Data Collection Endpoint (DCE)
   - Data Collection Rule (DCR) with `Custom-OutboundConnectivityLogs` stream

2. **RBAC Permissions:**
   ```bash
   # Get VyOS VM managed identity principal ID
   PRINCIPAL_ID=$(az vm identity show \
       --resource-group <rg-name> \
       --name <vyos-vm-name> \
       --query principalId -o tsv)
   
   # Get DCR resource ID
   DCR_ID=$(az monitor data-collection rule show \
       --resource-group <rg-name> \
       --name <dcr-name> \
       --query id -o tsv)
   
   # Grant "Monitoring Metrics Publisher" role
   az role assignment create \
       --assignee $PRINCIPAL_ID \
       --role "Monitoring Metrics Publisher" \
       --scope $DCR_ID
   ```

3. **VyOS Host:**
   - Whitelist file location: `/config/squid-whitelist/allowed_domains.txt`

### 1. Create Whitelist File on VyOS Host

```bash
# On VyOS host
configure
run mkdir -p /config/squid-whitelist
exit

# Create whitelist file
sudo tee /config/squid-whitelist/allowed_domains.txt << 'EOF'
# Domain whitelist - one domain per line
# Supports wildcard format: .cisco.com matches *.cisco.com
.cisco.com
.example.com
.microsoft.com
EOF

sudo chmod 644 /config/squid-whitelist/allowed_domains.txt
```

### 2. Build Squid Container

**Directory structure:**
```
squid-whitelist/
├── Dockerfile
├── squid.conf
├── squid-log-monitor.py
├── requirements.txt
└── supervisord.conf
```

**Dockerfile:**
```dockerfile
FROM alpine:latest

# Install required packages
RUN apk add --no-cache \
    squid \
    openssl \
    python3 \
    py3-pip \
    bash \
    supervisor

# Install Python dependencies
COPY requirements.txt /tmp/
RUN pip3 install --break-system-packages -r /tmp/requirements.txt

# Generate self-signed cert for Squid's internal use
RUN openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/C=US/ST=State/L=City/O=Org/CN=squid" \
    -keyout /etc/squid/key.pem -out /etc/squid/cert.pem && \
    chmod 600 /etc/squid/key.pem

# Copy configuration files
COPY squid.conf /etc/squid/squid.conf
COPY squid-log-monitor.py /usr/local/bin/squid-log-monitor.py
COPY supervisord.conf /etc/supervisord.conf

RUN chmod +x /usr/local/bin/squid-log-monitor.py

# Create directories
RUN mkdir -p /var/cache/squid /var/log/squid /var/run/squid && \
    chown -R squid:squid /var/cache/squid /var/log/squid /var/run/squid && \
    squid -z

EXPOSE 3129 3130

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]
```

**requirements.txt:**
```
azure-identity==1.25.1
azure-monitor-ingestion==1.1.0
```

**squid.conf:**
```
# Basic config
cache_dir ufs /var/cache/squid 100 16 256
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log
coredump_dir /var/cache/squid
pid_filename /var/run/squid/squid.pid

# HTTP interception
http_port 3129 intercept

# HTTPS interception with SSL splice
https_port 3130 intercept ssl-bump \
    cert=/etc/squid/cert.pem \
    key=/etc/squid/key.pem

# SSL bump - peek at SNI, then splice (don't decrypt)
ssl_bump peek step1
ssl_bump splice all

# ACLs for whitelisting - loaded from external file
acl allowed_ssl ssl::server_name "/etc/squid/allowed_domains.txt"
acl allowed_http dstdomain "/etc/squid/allowed_domains.txt"
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl CONNECT method CONNECT

# Deny non-standard ports
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports

# Allow whitelisted domains
http_access allow allowed_ssl
http_access allow allowed_http

# Deny everything else
http_access deny all
```

**squid-log-monitor.py:**
```python
#!/usr/bin/env python3
"""
Squid Log Monitor for VyOS SNI Whitelist
Monitors Squid proxy logs and sends allowed/blocked events to Azure Log Analytics
Uses Azure Managed Identity for authentication
"""

import os
import sys
import json
import time
import re
from datetime import datetime, timezone
from collections import deque
from urllib.parse import urlparse
from azure.identity import ManagedIdentityCredential
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import HttpResponseError
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class SquidLogMonitor:
    def __init__(self):
        # Get Log Analytics configuration from environment
        self.dce_endpoint = os.environ.get('DCE_ENDPOINT')
        self.dcr_immutable_id = os.environ.get('DCR_IMMUTABLE_ID')
        self.stream_name = os.environ.get('DCR_STREAM_NAME', 'Custom-OutboundConnectivityLogs')
        
        # Validate configuration
        if not all([self.dce_endpoint, self.dcr_immutable_id]):
            logger.error("Missing required environment variables: DCE_ENDPOINT, DCR_IMMUTABLE_ID")
            sys.exit(1)
        
        # Initialize Azure client with Managed Identity
        logger.info("Initializing Azure Managed Identity authentication...")
        self.credential = ManagedIdentityCredential()
        
        self.ingestion_client = LogsIngestionClient(
            endpoint=self.dce_endpoint,
            credential=self.credential,
            logging_enable=False
        )
        
        # Track processed log entries
        self.processed_entries = deque(maxlen=10000)
        
        # Squid log file
        self.squid_log_file = '/var/log/squid/access.log'
        self.squid_file_position = 0
        
        logger.info(f"Monitor initialized - DCE: {self.dce_endpoint}, Stream: {self.stream_name}")
    
    def parse_squid_log_line(self, line):
        """Parse Squid access log line"""
        try:
            # Standard Squid log format: timestamp elapsed client code/status bytes method URL
            parts = line.strip().split()
            if len(parts) < 7:
                return None
            
            # Parse timestamp
            timestamp_parts = parts[0].split('.')
            timestamp = float(timestamp_parts[0])
            
            # Parse other fields
            client_ip = parts[2]
            result_code = parts[3]
            bytes_size = parts[4]
            method = parts[5]
            url = parts[6]
            
            # Extract destination from URL
            destination = 'unknown'
            destination_port = None
            if url.startswith('http://') or url.startswith('https://'):
                parsed = urlparse(url)
                destination = parsed.hostname or 'unknown'
                destination_port = parsed.port
            elif ':' in url:  # CONNECT requests
                dest_parts = url.split(':')
                destination = dest_parts[0]
                destination_port = int(dest_parts[1]) if len(dest_parts) > 1 else None
            
            # Determine if allowed or blocked based on result code
            status_parts = result_code.split('/')
            squid_status = status_parts[0] if status_parts else 'UNKNOWN'
            http_code = int(status_parts[1]) if len(status_parts) > 1 and status_parts[1].isdigit() else 0
            
            # Squid status codes indicating blocked traffic
            blocked_statuses = ['TCP_DENIED', 'NONE']
            allowed_statuses = ['TCP_MISS', 'TCP_HIT', 'TCP_TUNNEL', 'TCP_REFRESH_HIT', 'TCP_REFRESH_MISS']
            
            if any(blocked in squid_status for blocked in blocked_statuses) or http_code == 403:
                action = 'blocked'
            elif any(allowed in squid_status for allowed in allowed_statuses):
                action = 'allowed'
            else:
                action = 'unknown'
            
            return {
                'TimeGenerated': datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
                'SourceIP': client_ip,
                'DestinationHost': destination,
                'DestinationPort': destination_port,
                'Action': action,
                'Protocol': 'HTTPS' if method == 'CONNECT' else 'HTTP',
                'Method': method,
                'URL': url,
                'BytesTransferred': int(bytes_size) if bytes_size.isdigit() else 0,
                'SquidStatus': squid_status,
                'HTTPCode': http_code,
                'LogType': 'squid_sni_filter'
            }
            
        except Exception as e:
            logger.error(f"Error parsing Squid log line: {e} - Line: {line[:100]}")
            return None
    
    def read_squid_logs(self):
        """Read new entries from Squid access log"""
        try:
            if not os.path.exists(self.squid_log_file):
                return []
            
            new_entries = []
            with open(self.squid_log_file, 'r') as f:
                # Seek to last position
                f.seek(self.squid_file_position)
                
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Check if we've already processed this entry
                    line_hash = hash(line)
                    if line_hash not in self.processed_entries:
                        entry = self.parse_squid_log_line(line)
                        if entry:
                            new_entries.append(entry)
                            self.processed_entries.append(line_hash)
                
                # Update file position
                self.squid_file_position = f.tell()
            
            return new_entries
            
        except Exception as e:
            logger.error(f"Error reading Squid logs: {e}")
            return []
    
    def send_log_events(self, events):
        """Send log events to Azure Log Analytics"""
        if not events:
            return
        
        try:
            # Send in batches of 100
            batch_size = 100
            for i in range(0, len(events), batch_size):
                batch = events[i:i + batch_size]
                
                self.ingestion_client.upload(
                    rule_id=self.dcr_immutable_id,
                    stream_name=self.stream_name,
                    logs=batch
                )
                
                logger.info(f"Sent {len(batch)} events to Log Analytics (Stream: {self.stream_name})")
            
        except HttpResponseError as e:
            logger.error(f"Failed to send logs to Azure: {e}")
        except Exception as e:
            logger.error(f"Unexpected error sending logs: {e}")
    
    def monitor_logs(self):
        """Monitor Squid logs continuously"""
        logger.info("Starting Squid log monitor")
        
        # Initial wait for Squid to start
        time.sleep(10)
        
        while True:
            try:
                # Read new log entries
                events = self.read_squid_logs()
                
                if events:
                    logger.debug(f"Found {len(events)} new events")
                    self.send_log_events(events)
                
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
            
            # Check every 30 seconds
            time.sleep(30)

if __name__ == "__main__":
    monitor = SquidLogMonitor()
    monitor.monitor_logs()
```

**supervisord.conf:**
```ini
[supervisord]
nodaemon=true
user=root
logfile=/dev/null
logfile_maxbytes=0
pidfile=/var/run/supervisord.pid

[program:squid]
command=/usr/sbin/squid -N -d 1
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
priority=1

[program:log-monitor]
command=/usr/local/bin/squid-log-monitor.py
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
environment=DCE_ENDPOINT="%(ENV_DCE_ENDPOINT)s",DCR_IMMUTABLE_ID="%(ENV_DCR_IMMUTABLE_ID)s",DCR_STREAM_NAME="%(ENV_DCR_STREAM_NAME)s"
priority=2
```

**Build and export:**
```bash
cd squid-whitelist
podman build -t squid-whitelist:latest .
podman save squid-whitelist:latest -o squid-whitelist.tar
```

### 3. Deploy to VyOS

**Transfer container:**
```bash
scp squid-whitelist.tar vyos@<router-ip>:/tmp/
```

**Load on VyOS:**
```bash
ssh vyos@<router-ip>
podman load -i /tmp/squid-whitelist.tar
rm /tmp/squid-whitelist.tar
```

### 4. Get Azure Configuration

On your Azure management machine:

```bash
# Get DCE endpoint
DCE_ENDPOINT=$(az monitor data-collection endpoint show \
    --resource-group <resource-group> \
    --name <dce-name> \
    --query logsIngestion.endpoint -o tsv)

# Get DCR immutable ID
DCR_IMMUTABLE_ID=$(az monitor data-collection rule show \
    --resource-group <resource-group> \
    --name <dcr-name> \
    --query immutableId -o tsv)

echo "DCE_ENDPOINT: $DCE_ENDPOINT"
echo "DCR_IMMUTABLE_ID: $DCR_IMMUTABLE_ID"
```

### 5. Configure VyOS

**Configuration parameters:**
- `<lan-interface>` - LAN interface (e.g., eth1)
- `<wan-interface>` - WAN interface (e.g., eth0)
- `<container-ip>` - Container IP address (e.g., 10.5.0.2)
- `<container-network>` - Container network CIDR (e.g., 10.5.0.0/24)
- `<dce-endpoint>` - Azure DCE endpoint from step 4
- `<dcr-immutable-id>` - Azure DCR ID from step 4

**VyOS commands:**
```bash
configure

# Create container network
set container network squid-net prefix <container-network>

# Define container with volume mount for whitelist
set container name squid-filter image squid-whitelist:latest
set container name squid-filter network squid-net address <container-ip>
set container name squid-filter restart on-failure

# Mount external whitelist file
set container name squid-filter volume whitelist source /config/squid-whitelist/allowed_domains.txt
set container name squid-filter volume whitelist destination /etc/squid/allowed_domains.txt
set container name squid-filter volume whitelist mode ro

# Set environment variables for Azure Log Analytics
set container name squid-filter environment DCE_ENDPOINT value '<dce-endpoint>'
set container name squid-filter environment DCR_IMMUTABLE_ID value '<dcr-immutable-id>'
set container name squid-filter environment DCR_STREAM_NAME value 'Custom-OutboundConnectivityLogs'

# NAT - redirect HTTP to container
set nat destination rule 100 description 'Redirect HTTP to Squid'
set nat destination rule 100 destination port 80
set nat destination rule 100 inbound-interface <lan-interface>
set nat destination rule 100 protocol tcp
set nat destination rule 100 translation address <container-ip>
set nat destination rule 100 translation port 3129

# NAT - redirect HTTPS to container
set nat destination rule 101 description 'Redirect HTTPS to Squid'
set nat destination rule 101 destination port 443
set nat destination rule 101 inbound-interface <lan-interface>
set nat destination rule 101 protocol tcp
set nat destination rule 101 translation address <container-ip>
set nat destination rule 101 translation port 3130

# Firewall - block UDP 443 (QUIC/HTTP3)
set firewall ipv4 name WAN-OUT default-action accept
set firewall ipv4 name WAN-OUT rule 100 action drop
set firewall ipv4 name WAN-OUT rule 100 description 'Block QUIC/HTTP3'
set firewall ipv4 name WAN-OUT rule 100 destination port 443
set firewall ipv4 name WAN-OUT rule 100 protocol udp

# Firewall - block direct TCP bypass (only allow from container)
set firewall ipv4 name WAN-OUT rule 200 action drop
set firewall ipv4 name WAN-OUT rule 200 description 'Block direct HTTP/HTTPS bypass'
set firewall ipv4 name WAN-OUT rule 200 destination port 80,443
set firewall ipv4 name WAN-OUT rule 200 protocol tcp
set firewall ipv4 name WAN-OUT rule 200 source address !<container-ip>

# Apply firewall to forward chain
set firewall ipv4 forward filter rule 10 action jump
set firewall ipv4 forward filter rule 10 jump-target WAN-OUT
set firewall ipv4 forward filter rule 10 outbound-interface <wan-interface>

commit
save
```

### 6. Verification

**Check container status:**
```bash
show container
show container log squid-filter
```

**Test from client behind VyOS:**
```bash
# Should succeed
curl -v https://www.cisco.com

# Should fail (connection denied)
curl -v https://www.google.com
```

**View container logs:**
```bash
show container log squid-filter
```

**Check Azure Log Analytics:**
```kusto
// Query for blocked connections in last 24 hours
OutboundConnectivityLogs_CL
| where TimeGenerated > ago(24h)
| extend LogData = parse_json(RawData)
| where LogData.Action == "blocked"
| project TimeGenerated, 
    SourceIP = LogData.SourceIP,
    Destination = LogData.DestinationHost,
    URL = LogData.URL,
    Action = LogData.Action
| order by TimeGenerated desc

// Query for allowed connections
OutboundConnectivityLogs_CL
| where TimeGenerated > ago(24h)
| extend LogData = parse_json(RawData)
| where LogData.Action == "allowed"
| project TimeGenerated, 
    SourceIP = LogData.SourceIP,
    Destination = LogData.DestinationHost,
    URL = LogData.URL,
    BytesTransferred = LogData.BytesTransferred
| order by TimeGenerated desc
```

## Whitelist Management

### Adding/Removing Domains

Edit the whitelist file on VyOS host:

```bash
# Edit whitelist
sudo vi /config/squid-whitelist/allowed_domains.txt

# Add domains (one per line)
.newdomain.com
.anotherdomain.net

# Reload Squid configuration without restarting container
podman exec squid-filter squid -k reconfigure
```

**Whitelist format:**
```
# Comments start with #
# Wildcard format: .domain.com matches *.domain.com
.cisco.com
.microsoft.com
.azure.com

# Exact domain (no wildcard)
specific.example.com
```

### Automated Whitelist Updates

Create a script for automated updates:

```bash
#!/bin/bash
# File: /config/scripts/update-whitelist.sh

WHITELIST_FILE="/config/squid-whitelist/allowed_domains.txt"

# Add new domain
add_domain() {
    local domain=$1
    if ! grep -q "^${domain}$" "$WHITELIST_FILE"; then
        echo "$domain" >> "$WHITELIST_FILE"
        echo "Added: $domain"
        podman exec squid-filter squid -k reconfigure
    else
        echo "Already exists: $domain"
    fi
}

# Remove domain
remove_domain() {
    local domain=$1
    sed -i "/^${domain}$/d" "$WHITELIST_FILE"
    echo "Removed: $domain"
    podman exec squid-filter squid -k reconfigure
}

# Usage
case "$1" in
    add)
        add_domain "$2"
        ;;
    remove)
        remove_domain "$2"
        ;;
    *)
        echo "Usage: $0 {add|remove} domain"
        exit 1
        ;;
esac
```

Usage:
```bash
/config/scripts/update-whitelist.sh add .newdomain.com
/config/scripts/update-whitelist.sh remove .olddomain.com
```

## Monitoring and Troubleshooting

### View Real-Time Logs

```bash
# Container logs (both Squid and monitor)
show container log squid-filter

# Follow logs in real-time
podman logs -f squid-filter
```

### Check Squid Status

```bash
# Check if Squid is running inside container
podman exec squid-filter ps aux | grep squid

# Check Squid configuration
podman exec squid-filter squid -k parse
```

### Monitor in Azure Log Analytics

**Dashboard Query - Connection Summary:**
```kusto
OutboundConnectivityLogs_CL
| where TimeGenerated > ago(1h)
| extend LogData = parse_json(RawData)
| summarize 
    Allowed = countif(LogData.Action == "allowed"),
    Blocked = countif(LogData.Action == "blocked")
| project Allowed, Blocked, Total = Allowed + Blocked
```

**Top Blocked Destinations:**
```kusto
OutboundConnectivityLogs_CL
| where TimeGenerated > ago(24h)
| extend LogData = parse_json(RawData)
| where LogData.Action == "blocked"
| summarize Count = count() by Destination = tostring(LogData.DestinationHost)
| order by Count desc
| take 20
```

**Connection Timeline:**
```kusto
OutboundConnectivityLogs_CL
| where TimeGenerated > ago(24h)
| extend LogData = parse_json(RawData)
| summarize 
    Allowed = countif(LogData.Action == "allowed"),
    Blocked = countif(LogData.Action == "blocked")
    by bin(TimeGenerated, 5m)
| render timechart
```

### Troubleshooting

**Container won't start:**
```bash
# Check container status
show container squid-filter

# View detailed logs
podman logs squid-filter

# Check if whitelist file exists and is readable
ls -la /config/squid-whitelist/allowed_domains.txt
```

**Logs not appearing in Azure:**
```bash
# Check if managed identity is configured
az vm identity show --resource-group <rg> --name <vm-name>

# Verify environment variables in container
podman exec squid-filter env | grep -E 'DCE|DCR'

# Check monitor logs inside container
podman logs squid-filter | grep monitor
```

**All traffic blocked:**
```bash
# Verify whitelist file content
podman exec squid-filter cat /etc/squid/allowed_domains.txt

# Check Squid ACL parsing
podman exec squid-filter squid -k parse

# Restart container
configure
restart container squid-filter
commit
```

**Traffic bypassing proxy:**
```bash
# Verify NAT rules
show nat destination rules

# Verify firewall rules
show firewall ipv4 forward filter

# Check that clients are on correct interface
show interfaces
```

## Maintenance

### Regular Tasks

**Weekly:**
- Review blocked connection logs in Azure Log Analytics
- Verify whitelist is current
- Check container health: `show container`

**Monthly:**
- Review allowed connections for anomalies
- Update container image if needed
- Backup whitelist: `cp /config/squid-whitelist/allowed_domains.txt /config/backups/`

### Container Updates

When updating the container image:

```bash
# Build new image
podman build -t squid-whitelist:latest .
podman save squid-whitelist:latest -o squid-whitelist.tar

# Transfer to VyOS
scp squid-whitelist.tar vyos@<router-ip>:/tmp/

# On VyOS
configure
delete container name squid-filter
commit
podman load -i /tmp/squid-whitelist.tar
rm /tmp/squid-whitelist.tar

# Recreate container (commands from step 5)
set container name squid-filter image squid-whitelist:latest
# ... (repeat all container config)
commit
save
```

### Backup and Recovery

**Backup configuration:**
```bash
# On VyOS
show configuration commands | grep -E 'container|nat destination rule 10[01]|firewall.*WAN-OUT'

# Backup whitelist
cp /config/squid-whitelist/allowed_domains.txt /config/backups/allowed_domains_$(date +%Y%m%d).txt
```

**Restore:**
```bash
# Restore whitelist
cp /config/backups/allowed_domains_YYYYMMDD.txt /config/squid-whitelist/allowed_domains.txt

# Reload Squid
podman exec squid-filter squid -k reconfigure
```

## Summary

This solution provides effective malware C2 blocking through domain whitelisting without requiring SSL/TLS decryption or client-side configuration. The whitelist is managed externally for easy updates, and all connection attempts are logged to Azure Log Analytics using managed identity authentication for security monitoring and threat analysis.

**Key Benefits:**
- No SSL decryption (maintains end-to-end encryption)
- No client configuration required
- Dynamic whitelist updates without container rebuild
- All traffic logged to Azure Log Analytics
- Secure authentication via Azure Managed Identity
- Effective against malware C2 communication
