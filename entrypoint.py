#!/usr/bin/env python3

import os
import subprocess
import sys
import json
import re
import logging
import signal
import time
from typing import List, Dict, Optional

# Configure logging
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger('wireguard-entrypoint')

# Configuration paths
CONFIG_DIR = "/etc/wireguard"
PRIVATE_KEY_FILE = f"{CONFIG_DIR}/privatekey"
PUBLIC_KEY_FILE = f"{CONFIG_DIR}/publickey"
CONFIG_FILE = f"{CONFIG_DIR}/wg0.conf"

# Global flag for graceful shutdown
shutdown_requested = False


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    global shutdown_requested
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_requested = True


def run_command(command: List[str], check: bool = True, input_data: Optional[str] = None) -> str:
    """
    Run a command safely without shell=True

    Args:
        command: List of command arguments
        check: Raise exception on non-zero exit code
        input_data: Optional stdin data

    Returns:
        Command stdout as string
    """
    try:
        result = subprocess.run(
            command,
            check=check,
            text=True,
            capture_output=True,
            input=input_data
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {' '.join(command)}")
        logger.error(f"Exit code: {e.returncode}")
        logger.error(f"Error output: {e.stderr}")
        if check:
            sys.exit(1)
        return ""


def generate_keys() -> str:
    """Generate WireGuard private and public keys if they don't exist"""
    if os.path.exists(PRIVATE_KEY_FILE):
        logger.info("Using existing WireGuard keys")
        with open(PUBLIC_KEY_FILE, 'r') as f:
            return f.read().strip()

    logger.info("Generating WireGuard keys...")

    # Generate private key
    private_key = run_command(["wg", "genkey"])

    with open(PRIVATE_KEY_FILE, 'w') as f:
        f.write(private_key + '\n')
    os.chmod(PRIVATE_KEY_FILE, 0o600)

    # Generate public key from private key
    public_key = run_command(["wg", "pubkey"], input_data=private_key)

    with open(PUBLIC_KEY_FILE, 'w') as f:
        f.write(public_key + '\n')
    os.chmod(PUBLIC_KEY_FILE, 0o600)

    logger.info(f"Generated new WireGuard keys")
    logger.info(f"Public key: {public_key}")

    return public_key


def validate_peer_config(peer: Dict) -> bool:
    """Validate peer configuration"""
    required_fields = ['public_key', 'allowed_ips']

    for field in required_fields:
        if field not in peer:
            logger.warning(f"Peer missing required field: {field}")
            return False

    # Validate public key format (base64, 44 chars including =)
    if not re.match(r'^[A-Za-z0-9+/]{43}=$', peer['public_key']):
        logger.warning(f"Invalid public key format: {peer['public_key']}")
        return False

    return True


def parse_peers(peers_str: str) -> List[Dict]:
    """
    Parse peers from environment variable.
    Supports two formats:
    1. Simple: "PublicKey:IP/CIDR,PublicKey:IP/CIDR"
    2. JSON: '[{"public_key":"...","allowed_ips":"...","persistent_keepalive":25}]'
    """
    if not peers_str:
        return []

    peers = []

    # Try JSON format first
    if peers_str.strip().startswith('['):
        try:
            peers_list = json.loads(peers_str)
            for peer in peers_list:
                if validate_peer_config(peer):
                    peers.append(peer)
            return peers
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON format in WG_PEERS: {e}")
            return []

    # Fall back to simple format
    for peer_str in peers_str.split(','):
        peer_str = peer_str.strip()
        if ':' not in peer_str:
            logger.warning(f"Invalid peer format (missing ':'): {peer_str}")
            continue

        parts = peer_str.split(':', 1)
        if len(parts) != 2:
            logger.warning(f"Invalid peer format: {peer_str}")
            continue

        public_key, allowed_ips = parts
        peer = {
            'public_key': public_key.strip(),
            'allowed_ips': allowed_ips.strip()
        }

        if validate_peer_config(peer):
            peers.append(peer)

    return peers


def generate_config(peers: List[Dict]):
    """Generate the WireGuard configuration file"""
    # Get environment variables
    wg_address = os.environ.get('WG_ADDRESS', '10.0.0.1/24')
    wg_port = os.environ.get('WG_PORT', '51820')
    wg_mtu = os.environ.get('WG_MTU', '')
    wg_post_up = os.environ.get('WG_POST_UP', '')
    wg_post_down = os.environ.get('WG_POST_DOWN', '')

    # Read private key
    with open(PRIVATE_KEY_FILE, 'r') as f:
        private_key = f.read().strip()

    # Create config
    config = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {wg_address}",
        f"ListenPort = {wg_port}",
    ]

    if wg_mtu:
        config.append(f"MTU = {wg_mtu}")

    if wg_post_up:
        config.append(f"PostUp = {wg_post_up}")

    if wg_post_down:
        config.append(f"PostDown = {wg_post_down}")

    # Add peers
    for peer in peers:
        config.extend([
            "",
            "[Peer]",
            f"PublicKey = {peer['public_key']}",
            f"AllowedIPs = {peer['allowed_ips']}"
        ])

        # Optional peer settings
        if 'endpoint' in peer:
            config.append(f"Endpoint = {peer['endpoint']}")

        if 'persistent_keepalive' in peer:
            config.append(f"PersistentKeepalive = {peer['persistent_keepalive']}")

        if 'preshared_key' in peer:
            config.append(f"PresharedKey = {peer['preshared_key']}")

    # Write config file
    with open(CONFIG_FILE, 'w') as f:
        f.write('\n'.join(config) + '\n')

    os.chmod(CONFIG_FILE, 0o600)
    logger.info(f"WireGuard configuration generated with {len(peers)} peer(s)")


def setup_ip_forwarding():
    """Enable IP forwarding if configured"""
    if os.environ.get('WG_ENABLE_IP_FORWARD', 'true').lower() != 'true':
        logger.info("IP forwarding disabled by configuration")
        return

    logger.info("Enabling IP forwarding")
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1\n')
        logger.info("IPv4 forwarding enabled")
    except Exception as e:
        logger.error(f"Failed to enable IP forwarding: {e}")


def setup_masquerade():
    """Setup NAT masquerading for VPN clients"""
    if os.environ.get('WG_ENABLE_MASQUERADE', 'false').lower() != 'true':
        logger.info("Masquerading disabled by configuration")
        return

    interface = os.environ.get('WG_INTERFACE', 'eth0')
    allowed_sources = os.environ.get('WG_ALLOWED_SOURCES', 'none')

    logger.info(f"Setting up masquerade on {interface} for {allowed_sources}")

    try:
        run_command([
            "iptables",
            "-t", "nat",
            "-A", "POSTROUTING",
            "-o", interface,
            "-s", allowed_sources,
            "-j", "MASQUERADE"
        ])
        logger.info("Masquerading configured successfully")
    except Exception as e:
        logger.error(f"Failed to setup masquerading: {e}")


def parse_port_forward(forward_str: str) -> Optional[Dict]:
    """
    Parse a port forward rule.
    Format: external_port:internal_ip:internal_port[:protocol]
    Example: "8080:10.0.0.4:11434:tcp"
    """
    parts = forward_str.strip().split(':')
    if len(parts) < 3 or len(parts) > 4:
        logger.warning(f"Invalid port forward format: {forward_str}")
        return None

    try:
        return {
            'external_port': int(parts[0]),
            'internal_ip': parts[1],
            'internal_port': int(parts[2]),
            'protocol': parts[3] if len(parts) == 4 else 'tcp'
        }
    except ValueError:
        logger.warning(f"Invalid port numbers in: {forward_str}")
        return None


def setup_port_forwards():
    """Setup port forwarding rules based on WG_PORT_FORWARDS env var"""
    forwards_str = os.environ.get('WG_PORT_FORWARDS', '')
    if not forwards_str:
        logger.info("No port forwards configured")
        return

    logger.info("Setting up port forwarding rules")

    for forward_str in forwards_str.split(','):
        forward = parse_port_forward(forward_str)
        if not forward:
            continue

        logger.info(
            f"Forwarding {forward['external_port']}/{forward['protocol']} "
            f"-> {forward['internal_ip']}:{forward['internal_port']}"
        )

        try:
            # DNAT rule (incoming)
            run_command([
                "iptables",
                "-t", "nat",
                "-A", "PREROUTING",
                "-p", forward['protocol'],
                "--dport", str(forward['external_port']),
                "-j", "DNAT",
                "--to-destination", f"{forward['internal_ip']}:{forward['internal_port']}"
            ])

            # Masquerade for the forwarded connection
            run_command([
                "iptables",
                "-t", "nat",
                "-A", "POSTROUTING",
                "-p", forward['protocol'],
                "-d", forward['internal_ip'],
                "--dport", str(forward['internal_port']),
                "-j", "MASQUERADE"
            ])
        except Exception as e:
            logger.error(f"Failed to setup port forward: {e}")


def cleanup():
    """Cleanup WireGuard and iptables on shutdown"""
    logger.info("Cleaning up...")
    try:
        run_command(["wg-quick", "down", "wg0"], check=False)
        logger.info("WireGuard interface stopped")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

def check_wireguard_status():
    """Check if WireGuard is running properly"""
    try:
        result = subprocess.run(
            ["wg", "show"],
            check=True,
            text=True,
            capture_output=True
        )
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    """Main entrypoint"""
    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    logger.info("Starting WireGuard container")

    # Ensure config directory exists
    os.makedirs(CONFIG_DIR, exist_ok=True)

    # Generate or load keys
    public_key = generate_keys()

    # Parse peers from environment
    peers_str = os.environ.get('WG_PEERS', '')
    peers = parse_peers(peers_str)

    if not peers:
        logger.warning("No valid peers configured. VPN will start but no clients can connect.")
        logger.warning("Set WG_PEERS environment variable to add peers.")

    # Generate WireGuard config
    generate_config(peers)

    # Enable IP forwarding
    setup_ip_forwarding()

    # Start WireGuard
    logger.info("Starting WireGuard interface")
    run_command(["wg-quick", "up", "wg0"])

    # Setup networking rules
    setup_masquerade()
    setup_port_forwards()

    # Log public key for easy access
    logger.info("=" * 60)
    logger.info(f"Server_public_key: {public_key}")
    logger.info("=" * 60)

    # Keep container running
    logger.info("WireGuard is running. Press Ctrl+C to stop.")

    try:
        while not shutdown_requested:
            time.sleep(30)
            if not check_wireguard_status():
                logger.error("WireGuard status check failed! Exiting...")
                cleanup()
                sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()
        logger.info("Shutdown complete")


if __name__ == "__main__":
    main()
