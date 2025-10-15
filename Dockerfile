FROM --platform=linux/amd64 alpine:latest

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
COPY squid-block.conf /etc/squid/squid-block.conf
COPY squid-monitor.conf /etc/squid/squid-monitor.conf
COPY squid-log-monitor.py /usr/local/bin/squid-log-monitor.py
COPY supervisord.conf /etc/supervisord.conf
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /usr/local/bin/squid-log-monitor.py /entrypoint.sh

# Create directories with proper ownership
# Note: squid -z will be run by entrypoint.sh after config is selected
RUN mkdir -p /var/cache/squid /var/log/squid /var/run/squid && \
    chown -R squid:squid /var/cache/squid /var/log/squid /var/run/squid

EXPOSE 3129 3130

# Health check - verify squid process is running
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD pgrep -x squid > /dev/null || exit 1

CMD ["/entrypoint.sh"]