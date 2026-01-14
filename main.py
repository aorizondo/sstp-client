#!/usr/bin/env python3
"""
SSTP Client - Main entry point.
"""
import argparse
import logging
import sys
import time

from sstp.client import SSTPClient
from port_binding import PortBinding


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='SSTP Client with Port Binding')
    parser.add_argument('--server', required=True, help='SSTP server hostname/IP')
    parser.add_argument('--port', type=int, default=443, help='SSTP server port (default: 443)')
    parser.add_argument('--user', required=True, help='Username for authentication')
    parser.add_argument('--pass', dest='password', required=True, help='Password for authentication')
    parser.add_argument('--bind-port', type=int, required=True, help='Local port to bind')
    parser.add_argument('--target', required=True, help='Target IP:PORT inside VPN (e.g., 192.168.1.100:80)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Parse target
    try:
        target_ip, target_port_str = args.target.split(':')
        target_port = int(target_port_str)
    except ValueError:
        print(f"Error: Invalid target format. Use IP:PORT (e.g., 192.168.1.100:80)")
        sys.exit(1)
    
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("SSTP Client with lwIP")
    logger.info("=" * 60)
    logger.info(f"Server: {args.server}:{args.port}")
    logger.info(f"User: {args.user}")
    logger.info(f"Local binding: localhost:{args.bind_port}")
    logger.info(f"VPN target: {target_ip}:{target_port}")
    logger.info("=" * 60)
    
    # Create SSTP client
    client = SSTPClient(
        server=args.server,
        username=args.user,
        password=args.password,
        port=args.port
    )
    
    # Create port binding
    binding = PortBinding(
        local_port=args.bind_port,
        target_ip=target_ip,
        target_port=target_port
    )
    
    try:
        # Connect SSTP
        logger.info("Connecting to SSTP server...")
        client.connect()
        
        # Start port binding
        logger.info("Starting port binding...")
        binding.start()
        
        logger.info("SSTP client ready! Press Ctrl+C to stop.")
        
        # Keep running
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        binding.stop()
        client.disconnect()
        logger.info("Goodbye!")


if __name__ == '__main__':
    main()
