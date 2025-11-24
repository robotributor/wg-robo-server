FROM alpine:3.18

# Install required packages
RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    ip6tables \
    nmap \
    python3 \
    py3-pip \
    iputils \
    curl \
    && rm -rf /var/cache/apk/*

# Create non-root user (for better security posture)
RUN addgroup -g 1000 wireguard && \
    adduser -D -u 1000 -G wireguard wireguard

# Create directory for WireGuard configuration
RUN mkdir -p /etc/wireguard && \
    chown -R wireguard:wireguard /etc/wireguard

# Copy entrypoint script
COPY entrypoint.py /usr/local/bin/entrypoint.py
RUN chmod +x /usr/local/bin/entrypoint.py

# Expose WireGuard port
EXPOSE 51820/udp

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wg show wg0 || exit 1

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.py"]
