# WireGuard Docker Container

A production-ready, secure WireGuard VPN server in a Docker container.

## Features

- Automatic key generation and management
- Easy peer configuration via environment variables
- Optional NAT masquerading
- Flexible port forwarding
- Health checks
- Graceful shutdown
- Configurable logging

## Quick Start

```bash
docker run -d \
  --name wireguard \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -p 51820:51820/udp \
  -e WG_PEERS='<peer-public-key>:10.0.0.2/32' \
  your-image-name
```

## Environment Variables

### Core Configuration

- **WG_ADDRESS** (default: `10.0.0.1/24`) - VPN server internal VPN network address and subnet
- **WG_PORT** (default: `51820`) - WireGuard listen port
- **WG_MTU** (default: empty) - Custom MTU size for the interface
- **WG_PEERS** (default: empty) - Allowed peers - this specifies who can connect to the server - <public-key>:<allowed-ips>. The public-key representing who, and the allowed-ips on what Wireguard IPs. The IPs are from the same network as the WG_ADDRESS

### Networking

- **WG_INTERFACE** (default: `eth0`) - Network interface for masquerading
- **WG_ALLOWED_SOURCES** (default: `none`) - Networks to masquerade towards. Can have multiple values, coma separated
- **WG_ENABLE_IP_FORWARD** (default: `true`) - Enable IPv4 forwarding
- **WG_ENABLE_MASQUERADE** (default: `false`) - Enable NAT masquerading
- **WG_PORT_FORWARDS** (default: empty) - Port forwarding rules

## Peer Configuration Format

### Simple Format

```
WG_PEERS='<public-key>:<allowed-ips>,<public-key>:<allowed-ips>'
```

Example:

```
WG_PEERS='OMeTfzxZ2a8m4vii2XwqkW5zjbds1mwznF45sKFP8Xk=:10.0.0.2/32'
```

### JSON Format (Advanced)

For more control, use JSON format with optional fields:

```json
WG_PEERS='[
  {
    "public_key": "OMeTfzxZ2a8m4vii2XwqkW5zjbds1mwznF45sKFP8Xk=",
    "allowed_ips": "10.0.0.2/32",
    "persistent_keepalive": 25,
    "endpoint": "203.0.113.10:51820",
    "preshared_key": "base64-encoded-preshared-key=="
  }
]'
```

## Port Forwarding Configuration

Format: `external_port:internal_ip:internal_port:protocol`

Example:

```bash
WG_PORT_FORWARDS='8080:10.0.0.4:80:tcp,8090:10.0.0.4:9000:tcp'
```

This forwards:
- External port 8080 (TCP) to 10.0.0.4:80
- External port 8090 (TCP) to 10.0.0.4:9000

## Docker Compose Example

```yaml
version: '3.8'

services:
  wireguard:
    image: your-wireguard-image:latest
    container_name: wireguard-vpn
    cap_add:
      - NET_ADMIN
      - NET_RAW
    ports:
      - "51820:51820/udp"
    environment:
      - WG_ADDRESS=10.100.0.1/24
      - WG_PORT=51820
      - WG_PEERS=6wM0acu/ctggIuQwkvbC4W89/vRfogG+kuwyIigm+Rc=:10.100.0.2/32
      - WG_ENABLE_MASQUERADE=true
      - LOG_LEVEL=INFO
    volumes:
      - wireguard-config:/etc/wireguard
    restart: unless-stopped

volumes:
  wireguard-config:
```

## Required Docker Capabilities

This container requires specific Linux capabilities to function:

- **NET_ADMIN** - For WireGuard interface management and configuration
- **NET_RAW** - For iptables rules and packet manipulation

Example with docker run:

```bash
docker run --cap-add=NET_ADMIN --cap-add=NET_RAW ...
```

## Data Persistence

The WireGuard keys and configuration are stored in `/etc/wireguard`. For best security regenerate server private keys in every run and extract them again. If you really need to persist these across container restarts, mount a volume:

```bash
docker run -v wireguard-config:/etc/wireguard ...
```

This ensures:
- Keys survive container recreation
- Configuration is preserved
- Easy backup of your VPN setup

## Example client setup on linux

### Generate client keys

```bash
PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)
echo "Private key: $PRIVATE_KEY"
echo "Public key:  $PUBLIC_KEY"
unset PRIVATE_KEY
unset PUBLIC_KEY
```

Store both keys in your password manager and make sure the private key is never shared with anyone. Output will look something like this:
```
Private key: yI6oZMyUwxcAAPFFYZ5C4J7oPHXkKkBGeyoZaUq+pkM=
Public key:  ORvc2GJvq1mSOPXSIhg8tWhQ1Lr6t2XJwtIrqfWDGEE=`
```

Each key starts with a character and ends up with '=' including.

### Network Manager setup

In case you are using Network Manager in linux, it is preferable to do your Wireguard setup within it. If you prefer to manage your own local wg.conf files, it is better to disable Network Manager

1. Open the Network Manager in Linux.
2. Add a new connection of type WireGuard.
3. On the tab "WireGuard Interface" fill up your Private Key in the field.
4. Click on the Peers button. Here we are adding the server details
5. Peer 1 Public Key - fill up the Server Public Key. You can get it from the logs of the running container. For example:
```
=========================================================================
Server_public_key: NhScYc6sRvo7rjLTsBYRDA3p4V3EaVFjN2kfeVaRan0=
=========================================================================
```
6. Allowed IPs - this specifies the networks your computer will be routing trough the VPN. You need the address passed as WG_ADDRESS as one of them. If you want to route all internet traffic via the VPN add 0.0.0.0/0.
7. Endpoint Address - This is the address on which the Server will be listening. If it is outside of your local network, you will need to specify the real world IP address.
8. Endpoint Port: Default is 51820, specified with the WG_PORT variable.
9. Save the peers and open the IPv4 Section - Switch it to "Manual" Method
10. [Optional] Write a DNS server - for example 9.9.9.9 - make sure to add it to the Allowed IPs list for the DNS traffic to be routed via the VPN.
11. Add an IP address - For example 10.0.0.2 with Netmask 255.255.255.255. This is the same IP address that you passed to the server within the WG_PEERS variiable.
12. Gateway is not needed and will default to 0.0.0.0
13. On the tab "WireGuard Interface" fill up MTU to 1400

Now you can connect to your Wireguard VPN.


## Security Considerations

### Key Management

- Private keys are stored with 0600 permissions (readable only by root)
- Keys are generated automatically on first run if they don't exist
- Mount the config volume to prevent key regeneration

### Input Validation

- All peer public keys are validated against WireGuard format
- IP addresses and ports are validated before use
- Invalid configurations are logged and skipped

### No Shell Execution

- The entrypoint uses subprocess without shell=True
- This prevents command injection vulnerabilities
- All commands are executed directly

### Minimal Attack Surface

- Alpine Linux base image minimizes installed packages
- Only essential runtime dependencies are included
- Regular security updates recommended

## Troubleshooting

### Check WireGuard Status

```bash
docker exec wireguard wg show
```

### View Logs

```bash
docker logs -f wireguard
```

### Get Public Key

The public key is logged on startup and also saved to `/etc/wireguard/publickey`:

```bash
docker exec wireguard cat /etc/wireguard/publickey
```

### Verify Peers

```bash
docker exec wireguard wg show wg0 peers
```

## Common Issues

**Container won't start**: Check that you've added `NET_ADMIN` and `NET_RAW` capabilities.

**Peers can't connect**: Verify peer public keys are correct and `WG_PEERS` is properly formatted.

**Port forwarding doesn't work**: Ensure the internal service is reachable at the specified IP address.

**No internet for VPN clients**: Enable masquerading with `WG_ENABLE_MASQUERADE=true` and verify IP forwarding is enabled.

## Building from Source

```bash
git clone <repository-url>
cd wireguard-docker
docker build -t my-wireguard:latest .
```


## Contributing

Contributions are welcome. Please ensure:
- Code follows the existing style
- Security best practices are maintained
- Documentation is updated
- Changes are tested before submission

## Support

For issues, feature requests, or questions, please open an issue on the project repository.
