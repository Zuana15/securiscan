#!/usr/bin/env python3
"""
SecuriScan Port Scanner Module
Scans target for open TCP ports and identifies running services.
"""

import socket
import sys
import json
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class PortScanner:
    def __init__(self, target, timeout=1):
        """
        Initialize port scanner.
        
        Args:
            target (str): Target hostname or IP address
            timeout (int): Connection timeout in seconds
        """
        self.target = target
        self.timeout = timeout
        self.open_ports = []
        self.services = {}
    
    def scan_port(self, port):
        """
        Scan a single port to check if it's open.
        
        Args:
            port (int): Port number to scan
            
        Returns:
            tuple: (port_number, is_open, service_info) or None if error
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((self.target, port))
            
            if result == 0:  # Port is open!
                service = self._grab_banner(sock, port)
                return (port, True, service)
            
            sock.close()
            return (port, False, None)
            
        except Exception as e:
            return (port, False, None)
    
    def _grab_banner(self, sock, port):
        """
        Try to grab service banner from open port.
        
        Args:
            sock: Socket object
            port (int): Port number
            
        Returns:
            str: Service banner or "Unknown"
        """
        try:
            # Send empty data or HTTP request for common ports
            if port in [80, 8080, 8000, 8888]:
                sock.send(b'HEAD / HTTP/1.0\r\nHost: ' + self.target.encode() + b'\r\n\r\n')
            elif port in [21, 25, 110, 143]:
                sock.send(b'\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else "Open (no banner)"
        except:
            return "Open (no banner)"
    
    def scan_range(self, start_port=1, end_port=1024, max_threads=100):
        """
        Scan a range of ports using multi-threading.
        
        Args:
            start_port (int): First port to scan
            end_port (int): Last port to scan
            max_threads (int): Maximum concurrent threads
            
        Returns:
            dict: Scan results
        """
        print(f"[+] Starting scan on {self.target}")
        print(f"[+] Scanning ports {start_port}-{end_port}...")
        
        self.open_ports = []
        self.services = {}
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all port scans
            futures = {
                executor.submit(self.scan_port, port): port 
                for port in range(start_port, end_port + 1)
            }
            
            # Collect results as they complete
            for future in as_completed(futures):
                port, is_open, service = future.result()
                if is_open:
                    self.open_ports.append(port)
                    self.services[port] = service
                    print(f"[!] Port {port} OPEN - {service}")
        
        return self.get_results()
    
    def get_results(self):
        """
        Get formatted scan results.
        
        Returns:
            dict: Results dictionary
        """
        return {
            "target": self.target,
            "scan_type": "port_scan",
            "timestamp": datetime.now().isoformat(),
            "total_ports_scanned": len(range(1, 1025)),  # Approximate
            "open_ports_count": len(self.open_ports),
            "open_ports": self.open_ports,
            "services": {str(k): v for k, v in self.services.items()},
            "status": "completed"
        }


def main():
    """Main entry point when run from command line."""
    # Simple test mode
    if len(sys.argv) < 2:
        print("Usage: python port_scanner.py <target> [start_port] [end_port]")
        print("Example: python port_scanner.py example.com 1 100")
        sys.exit(1)
    
    target = sys.argv[1]
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 100  # Small range for testing
    
    scanner = PortScanner(target, timeout=2)
    results = scanner.scan_range(start_port, end_port, max_threads=50)
    
    # Output as JSON (for Next.js to consume)
    print("\n--- RESULTS (JSON) ---")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()