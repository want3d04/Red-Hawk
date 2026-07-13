#!/usr/bin/env python3
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor

from core.logger import logger
from core.config import Config

class ReconScanner:
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.threads = self.config.get('scanner.threads', 50)
        self.timeout = self.config.get('scanner.timeout', 10)
        self.results = []
        self.wordlist = self._load_wordlist()
    
    def _load_wordlist(self) -> list:
        return [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'blog', 'dev', 'admin', 'forum', 'news', 'vpn',
            'mysql', 'old', 'support', 'mobile', 'mx', 'static', 'docs',
            'beta', 'shop', 'secure', 'demo', 'wiki', 'media', 'email',
            'images', 'img', 'download', 'dns', 'stats', 'dashboard',
            'portal', 'manage', 'start', 'info', 'app', 'login', 'panel',
            'api', 'cdn', 'cloud', 'remote', 'backup', 'data', 'files',
            'video', 'audio', 'stream', 'proxy', 'cache', 'mirror',
            'stage', 'testing', 'qa', 'staging', 'production', 'live'
        ]
    
    def scan_subdomains(self, domain: str) -> dict:
        """Subdomain enumeration"""
        logger.info(f"Enumerating subdomains for {domain}")
        
        found = []
        
        def check_subdomain(sub: str) -> str:
            full = f"{sub}.{domain}"
            try:
                dns.resolver.resolve(full, 'A')
                return full
            except:
                try:
                    resp = requests.get(f"http://{full}", timeout=self.timeout/2)
                    if resp.status_code < 500:
                        return full
                except:
                    pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(check_subdomain, self.wordlist)
            found = [r for r in results if r]
        
        results = {
            'domain': domain,
            'type': 'subdomain_scan',
            'subdomains': sorted(found)
        }
        self.results.append(results)
        return results
    
    def get_results(self) -> list:
        return self.results