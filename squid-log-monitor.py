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
        self.proxy_mode = os.environ.get('PROXY_MODE', 'block')
        
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
        
        # Validate whitelist file exists (especially important in block mode)
        whitelist_file = '/etc/squid/allowed_domains.txt'
        if not os.path.exists(whitelist_file):
            logger.warning(f"Whitelist file {whitelist_file} not found!")
            if self.proxy_mode == 'block':
                logger.warning("Running in block mode without whitelist - all traffic will be blocked!")
        else:
            with open(whitelist_file, 'r') as f:
                domain_count = sum(1 for line in f if line.strip() and not line.strip().startswith('#'))
                logger.info(f"Whitelist loaded with {domain_count} domains")
        
        logger.info(f"Monitor initialized - DCE: {self.dce_endpoint}, Stream: {self.stream_name}, Mode: {self.proxy_mode}")
    
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
            
            # In monitor mode, everything is "monitored" (allowed but logged)
            if self.proxy_mode == 'monitor':
                # Squid status codes indicating traffic flow
                successful_statuses = ['TCP_MISS', 'TCP_HIT', 'TCP_TUNNEL', 'TCP_REFRESH_HIT', 'TCP_REFRESH_MISS']
                
                if any(success in squid_status for success in successful_statuses):
                    action = 'monitored'
                else:
                    action = 'error'
            else:
                # Block mode - determine if allowed or blocked
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
                'LogType': 'squid_sni_filter',
                'ProxyMode': self.proxy_mode
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