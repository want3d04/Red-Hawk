#!/usr/bin/env python3
# core/utils.py - Utility Functions

import re
import socket
from urllib.parse import urlparse

def validate_url(url: str) -> str:
    if not re.match(r'^https?://', url):
        url = 'http://' + url
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    return url

def get_service_name(port: int) -> str:
    services = {
        20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC',
        139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
    }
    return services.get(port, 'Unknown')

def parse_port_range(range_str: str) -> list:
    ports = []
    if '-' in range_str:
        start, end = range_str.split('-')
        ports = list(range(int(start.strip()), int(end.strip()) + 1))
    elif ',' in range_str:
        ports = [int(p.strip()) for p in range_str.split(',')]
    else:
        ports = [int(range_str)]
    return ports