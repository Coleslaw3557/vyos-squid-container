# VyOS Squid SNI Whitelist Container

A containerized Squid proxy for VyOS that implements domain whitelisting using SNI (Server Name Indication) inspection. This container inspects HTTPS traffic without decryption and sends all connection logs to Azure Log Analytics.

## Purpose

Block malware command-and-control (C2) communication by implementing a domain whitelist that only allows traffic to approved domains. All connection attempts (allowed and blocked) are logged to Azure Log Analytics for monitoring and threat analysis.

## Features

- **SNI-based filtering**: Inspects HTTPS traffic without SSL/TLS decryption
- **External whitelist management**: Domain whitelist mounted from VyOS host
- **Azure Log Analytics integration**: Automatic log forwarding using Azure Managed Identity
- **No client configuration required**: Transparent proxy via VyOS NAT rules
- **Real-time monitoring**: Python script monitors Squid logs and forwards to Azure
- **Monitor mode**: Record all traffic without blocking to establish baseline before enforcement

## Architecture

```
Client → VyOS NAT → Squid Container → Internet
         (redirect)  (SNI inspection)   (if allowed)
                          ↓
                    Log Monitor → Azure Log Analytics
```

## Prerequisites

### Azure Resources
- VyOS VM with system-assigned managed identity enabled
- Log Analytics workspace
- Data Collection Endpoint (DCE)
- Data Collection Rule (DCR) with `Custom-OutboundConnectivityLogs` stream
- "Monitoring Metrics Publisher" role assigned to VM's managed identity on the DCR

### VyOS Host
- Podman installed
- Whitelist file at `/config/squid-whitelist/allowed_domains.txt`

## Quick Start

### 1. Build the Container

```bash
# Clone this repository
git clone <repository-url>
cd vyos-squid-container

# Build the container for amd64 platform (VyOS architecture)
# Option 1: Using make
make build-amd64

# Option 2: Using build script
./build-amd64.sh

# Option 3: Direct podman command
podman build --platform linux/amd64 -t squid-whitelist:latest .

# Export for transfer to VyOS
make save
# or
podman save squid-whitelist:latest -o squid-whitelist.tar
```

**Note**: If building on Apple Silicon (M1/M2) or other ARM platforms, the `--platform linux/amd64` flag is required to ensure compatibility with VyOS x86_64 architecture.

**Troubleshooting Architecture Issues:**
- If `podman inspect` shows `arm64` instead of `amd64`, try using Docker: `docker build --platform linux/amd64 -t squid-whitelist:latest .`
- Alternative: Use buildah: `buildah bud --platform linux/amd64 -t squid-whitelist:latest .`
- Last resort: Build on an actual x86_64 machine

### 2. Deploy to VyOS

```bash
# Transfer to VyOS
scp squid-whitelist.tar vyos@<router-ip>:/tmp/

# On VyOS, load the container
ssh vyos@<router-ip>
podman load -i /tmp/squid-whitelist.tar
rm /tmp/squid-whitelist.tar
```

### 3. Create Whitelist File on VyOS

```bash
# On VyOS
sudo mkdir -p /config/squid-whitelist
sudo tee /config/squid-whitelist/allowed_domains.txt << 'EOF'
# Domain whitelist - one domain per line
# Wildcard format: .domain.com matches *.domain.com
.microsoft.com
.azure.com
.example.com
EOF
```

### 4. Get Azure Configuration

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
```

### 5. Configure VyOS

```bash
configure

# Container network
set container network squid-net prefix 10.5.0.0/24

# Container with whitelist mount
set container name squid-filter image squid-whitelist:latest
set container name squid-filter network squid-net address 10.5.0.2
set container name squid-filter restart on-failure
set container name squid-filter volume whitelist source /config/squid-whitelist/allowed_domains.txt
set container name squid-filter volume whitelist destination /etc/squid/allowed_domains.txt
set container name squid-filter volume whitelist mode ro

# Azure Log Analytics environment variables
set container name squid-filter environment DCE_ENDPOINT value '<dce-endpoint>'
set container name squid-filter environment DCR_IMMUTABLE_ID value '<dcr-immutable-id>'
set container name squid-filter environment DCR_STREAM_NAME value 'Custom-OutboundConnectivityLogs'

# Proxy mode: 'monitor' to log all traffic, 'block' to enforce whitelist
set container name squid-filter environment PROXY_MODE value 'monitor'

# NAT rules
set nat destination rule 100 description 'Redirect HTTP to Squid'
set nat destination rule 100 destination port 80
set nat destination rule 100 inbound-interface eth1
set nat destination rule 100 protocol tcp
set nat destination rule 100 translation address 10.5.0.2
set nat destination rule 100 translation port 3129

set nat destination rule 101 description 'Redirect HTTPS to Squid'
set nat destination rule 101 destination port 443
set nat destination rule 101 inbound-interface eth1
set nat destination rule 101 protocol tcp
set nat destination rule 101 translation address 10.5.0.2
set nat destination rule 101 translation port 3130

commit
save
```

## Operating Modes

### Monitor Mode
- **Purpose**: Establish baseline of accessed domains before enforcing whitelist
- **Behavior**: All traffic is allowed and logged with action='monitored'
- **Use case**: Initial deployment to discover legitimate domains
- **Configuration**: `PROXY_MODE=monitor`

### Block Mode
- **Purpose**: Enforce domain whitelist for security
- **Behavior**: Only whitelisted domains allowed, others blocked
- **Use case**: Production deployment after baseline established
- **Configuration**: `PROXY_MODE=block` (default)

## Container Components

### Squid Configuration
- **Port 3129**: HTTP interception
- **Port 3130**: HTTPS interception with SNI inspection
- **SSL Bump**: Peek at SNI, then splice (no decryption)
- **ACLs**: Domain whitelist loaded from `/etc/squid/allowed_domains.txt`
- **Dual configs**: Separate configs for monitor and block modes

### Log Monitor Script
- Monitors `/var/log/squid/access.log`
- Parses Squid log entries
- Sends events to Azure Log Analytics via Data Collection API
- Uses Azure Managed Identity for authentication
- Includes proxy mode in log entries

### Process Management
- Supervisord manages both Squid and the log monitor
- Automatic restart on failure
- Environment variables passed to log monitor

## Whitelist Management

### Format
```
# Comments start with #
# Wildcard domains
.microsoft.com
.azure.com

# Exact domain match
specific.example.com
```

### Update Whitelist
```bash
# Edit whitelist on VyOS
sudo vi /config/squid-whitelist/allowed_domains.txt

# Reload Squid configuration
podman exec squid-filter squid -k reconfigure
```

## Monitoring

### Container Logs
```bash
# View logs
show container log squid-filter

# Follow logs
podman logs -f squid-filter
```

### Azure Log Analytics Queries

```kusto
// Monitor mode - All accessed domains
OutboundConnectivityLogs_CL
| where TimeGenerated > ago(24h)
| extend LogData = parse_json(RawData)
| where LogData.ProxyMode == "monitor"
| summarize Count = count() by Destination = tostring(LogData.DestinationHost)
| order by Count desc
| take 50

// Generate whitelist from monitor mode data
OutboundConnectivityLogs_CL
| where TimeGenerated > ago(7d)
| extend LogData = parse_json(RawData)
| where LogData.ProxyMode == "monitor" and LogData.Action == "monitored"
| summarize Count = count() by Domain = tostring(LogData.DestinationHost)
| where Count > 10  // Only domains accessed more than 10 times
| project Domain = strcat(".", Domain)  // Add wildcard prefix
| order by Domain asc

// Blocked connections (block mode)
OutboundConnectivityLogs_CL
| where TimeGenerated > ago(24h)
| extend LogData = parse_json(RawData)
| where LogData.Action == "blocked"
| project TimeGenerated, 
    SourceIP = LogData.SourceIP,
    Destination = LogData.DestinationHost,
    URL = LogData.URL

// Top blocked destinations
OutboundConnectivityLogs_CL
| where TimeGenerated > ago(24h)
| extend LogData = parse_json(RawData)
| where LogData.Action == "blocked"
| summarize Count = count() by Destination = tostring(LogData.DestinationHost)
| order by Count desc
| take 20
```

## Troubleshooting

### Container won't start
```bash
# Check status
show container squid-filter

# View detailed logs
podman logs squid-filter

# Verify whitelist file exists
ls -la /config/squid-whitelist/allowed_domains.txt
```

### Logs not appearing in Azure
```bash
# Check managed identity
az vm identity show --resource-group <rg> --name <vm-name>

# Verify environment variables
podman exec squid-filter env | grep -E 'DCE|DCR'

# Check monitor logs
podman logs squid-filter | grep -i error
```

### All traffic blocked
```bash
# Verify whitelist content
podman exec squid-filter cat /etc/squid/allowed_domains.txt

# Check Squid configuration
podman exec squid-filter squid -k parse

# Test Squid directly
podman exec squid-filter curl -x localhost:3129 http://example.com
```

## Development

### Project Structure
```
vyos-squid-container/
├── Dockerfile              # Container build file
├── squid-block.conf       # Squid configuration for block mode
├── squid-monitor.conf     # Squid configuration for monitor mode
├── squid-log-monitor.py   # Azure log forwarding script
├── requirements.txt       # Python dependencies
├── supervisord.conf       # Process management
├── entrypoint.sh          # Mode switching script
└── README.md             # This file
```

### Building Locally
```bash
# Build container for amd64 platform
podman build --platform linux/amd64 -t squid-whitelist:latest .

# For multi-platform builds (if using Docker Buildx)
docker buildx build --platform linux/amd64,linux/arm64 -t squid-whitelist:latest .

# Test run in monitor mode (requires whitelist file)
podman run --rm \
  --platform linux/amd64 \
  -v ./test-allowed_domains.txt:/etc/squid/allowed_domains.txt:ro \
  -e DCE_ENDPOINT=https://example.datacollection.azure.com \
  -e DCR_IMMUTABLE_ID=dcr-xxxxxxxx \
  -e PROXY_MODE=monitor \
  -p 3129:3129 -p 3130:3130 \
  squid-whitelist:latest

# Test run in block mode
podman run --rm \
  --platform linux/amd64 \
  -v ./test-allowed_domains.txt:/etc/squid/allowed_domains.txt:ro \
  -e DCE_ENDPOINT=https://example.datacollection.azure.com \
  -e DCR_IMMUTABLE_ID=dcr-xxxxxxxx \
  -e PROXY_MODE=block \
  -p 3129:3129 -p 3130:3130 \
  squid-whitelist:latest
```

### Switching Modes on VyOS

```bash
# Switch to monitor mode (log all traffic)
configure
set container name squid-filter environment PROXY_MODE value 'monitor'
commit
restart container squid-filter

# Switch to block mode (enforce whitelist)
configure
set container name squid-filter environment PROXY_MODE value 'block'
commit
restart container squid-filter

# Check current mode
show container squid-filter | grep PROXY_MODE
```

## Security Considerations

- No SSL/TLS decryption - maintains end-to-end encryption
- Uses Azure Managed Identity - no credentials in container
- Read-only whitelist mount - container cannot modify whitelist
- Minimal Alpine Linux base image
- Non-root Squid process

## License

This project is licensed under the MIT License - see the LICENSE file for details.