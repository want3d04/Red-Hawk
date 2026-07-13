#!/usr/bin/env python3

import os
import sys
import time
import json
from datetime import datetime
from colorama import Fore, Style, init
import requests
requests.packages.urllib3.disable_warnings()

init(autoreset=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import Config
from core.logger import logger
from core.utils import validate_url
from modules.web_scanner import WebScanner
from modules.network_scanner import NetworkScanner
from modules.recon_scanner import ReconScanner

class RedHawk:
    def __init__(self):
        self.start_time = datetime.now()
        self.config = Config()
        self.results = []
        self.vuln_count = 0
        self.web_scanner = WebScanner(self.config)
        self.network_scanner = NetworkScanner(self.config)
        self.recon_scanner = ReconScanner(self.config)
    
    def banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        banner = """
    ██████╗ ███████╗██████╗ ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
    ██╔══██╗██╔════╝██╔══██╗██║  ██║██╔══██╗██║    ██║██║ ██╔╝
    ██████╔╝█████╗  ██║  ██║███████║███████║██║ █╗ ██║█████╔╝ 
    ██╔══██╗██╔══╝  ██║  ██║██╔══██║██╔══██║██║███╗██║██╔═██╗ 
    ██║  ██║███████╗██████╔╝██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
        """
        print(Fore.RED + Style.BRIGHT + banner)
        print(Fore.CYAN + "╔══════════════════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + Style.BRIGHT + "  ⚡ RedHawk v1.0.0 | scanning tool for pentesting | Author : want3d ".center(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        runtime = datetime.now() - self.start_time
        print(Fore.CYAN + "║" + Fore.GREEN + f"  Session: {self.start_time.strftime('%Y%m%d_%H%M%S')}  |  Active: {str(runtime).split('.')[0]}".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════════════╝")
    
    def show_menu(self):
        self.banner()
        
        print(Fore.CYAN + "\n╔══════════════════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + Style.BRIGHT + "🎯 REDHAWK MAIN MENU 🎯".center(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        
        menu_items = [
            ("1", "Web Scanner", "SQLi, XSS, LFI, RFI, +15 more"),
            ("2", "Port Scanner", "Discover open ports and services"),
            ("3", "Subdomain Scanner", "Enumerate subdomains"),
            ("4", "Show Results", "Display scan results"),
            ("5", "Generate Report", "HTML, TXT, PDF, JSON"),
            ("6", "Settings", "Configure framework"),
            ("7", "Clear Results", "Reset session data"),
            ("0", "Exit", "Terminate session")
        ]
        
        for num, name, desc in menu_items:
            print(Fore.CYAN + "║  " + Fore.GREEN + Style.BRIGHT + f"[{num}]" + Fore.WHITE + f" {name}".ljust(32) + Fore.CYAN + "│" + Style.DIM + f" {desc}".ljust(30) + Fore.CYAN + "║")
        
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        
        threads = self.config.get('scanner.threads', 50)
        timeout = self.config.get('scanner.timeout', 10)
        results_count = len(self.results)
        
        status = f"  ⚡ Threads: {threads}  │  ⏱️  Timeout: {timeout}s  │  📊 Scans: {results_count}  │  🛡️  Vulns: {self.vuln_count}"
        print(Fore.CYAN + "║" + Fore.WHITE + status.ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════════════╝")
        print("")
    
    def get_target(self, prompt):
        return input(Fore.YELLOW + f"  ┌─[{prompt}]\n  └──╼ $ " + Fore.WHITE)
    
    def run_web_scanner(self):
        target = self.get_target("Target URL")
        if not target:
            return
        
        print(Fore.CYAN + "\n╔══════════════════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + Style.BRIGHT + "                    🔍 WEB APPLICATION SCAN".center(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════════════╝\n")
        
        result = self.web_scanner.scan(target)
        self.results.append(result)
        self.vuln_count += self.web_scanner.vuln_count
        self._show_web_results(result)
    
    def _show_web_results(self, result):
        vulns = result.get('vulnerabilities', [])
        
        print(Fore.CYAN + "\n╔══════════════════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + Style.BRIGHT + "                    📋 VULNERABILITY SUMMARY".center(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        
        if vulns:
            sev_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for v in vulns:
                sev = v.get('severity', 'Medium')
                if sev in sev_counts:
                    sev_counts[sev] += 1
            
            print(Fore.CYAN + "║" + Fore.RED + Style.BRIGHT + f"  [!] Total Vulnerabilities: {len(vulns)}".ljust(68) + Fore.CYAN + "║")
            print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
            
            for sev, count in sev_counts.items():
                if count > 0:
                    color = Fore.RED if sev == 'Critical' else Fore.YELLOW if sev == 'High' else Fore.CYAN
                    print(Fore.CYAN + "║  " + color + f"{sev}:".ljust(12) + Fore.WHITE + f"{count}".ljust(54) + Fore.CYAN + "║")
            
            print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
            print(Fore.CYAN + "║" + Fore.YELLOW + "  DETAILS:".ljust(68) + Fore.CYAN + "║")
            
            for v in vulns[:8]:
                v_type = v.get('type', 'Unknown')[:30]
                v_sev = v.get('severity', 'N/A')
                color = Fore.RED if v_sev == 'Critical' else Fore.YELLOW if v_sev == 'High' else Fore.WHITE
                print(Fore.CYAN + "║  " + color + f"→ {v_type}".ljust(40) + Style.DIM + f"[{v_sev}]".ljust(26) + Fore.CYAN + "║")
            
            if len(vulns) > 8:
                print(Fore.CYAN + "║  " + Style.DIM + f"... and {len(vulns)-8} more".ljust(66) + Fore.CYAN + "║")
        else:
            print(Fore.CYAN + "║" + Fore.GREEN + Style.BRIGHT + "  ✓ No vulnerabilities found!".center(68) + Fore.CYAN + "║")
        
        if result.get('directories'):
            print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
            print(Fore.CYAN + "║" + Fore.CYAN + f"  [i] Directories Found: {len(result['directories'])}".ljust(68) + Fore.CYAN + "║")
        
        if result.get('info', {}).get('technologies'):
            tech = ', '.join(result['info']['technologies'][:5])
            print(Fore.CYAN + "║" + Fore.CYAN + f"  [i] Technologies: {tech}".ljust(68) + Fore.CYAN + "║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════════════╝")
        input(Fore.CYAN + "\n  Press Enter to continue...")
    
    def run_port_scan(self):
        target = self.get_target("Target IP/Domain")
        if not target:
            return
        port_range = input(Fore.YELLOW + "  Port range (1-1000): " + Fore.WHITE) or "1-1000"
        
        print(Fore.CYAN + "\n╔══════════════════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + Style.BRIGHT + "                    🔌 PORT SCAN RESULTS".center(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        print(Fore.CYAN + "║" + Fore.WHITE + f"  Target: {target}".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        
        result = self.network_scanner.scan_port(target, port_range)
        self.results.append(result)
        
        ports = result.get('open_ports', [])
        if ports:
            print(Fore.CYAN + "║" + Fore.GREEN + Style.BRIGHT + f"  [+] Found {len(ports)} open ports".ljust(68) + Fore.CYAN + "║")
            print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
            for p in ports[:15]:
                port_info = f"  │  {p['port']}  │  {p['service']}"
                print(Fore.CYAN + "║" + Fore.WHITE + port_info.ljust(68) + Fore.CYAN + "║")
        else:
            print(Fore.CYAN + "║" + Fore.YELLOW + "  [-] No open ports found".ljust(68) + Fore.CYAN + "║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════════════╝")
        input(Fore.CYAN + "\n  Press Enter to continue...")
    
    def run_subdomain(self):
        target = self.get_target("Target Domain")
        if not target:
            return
        
        print(Fore.CYAN + "\n╔══════════════════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + Style.BRIGHT + "                    🌐 SUBDOMAIN SCAN RESULTS".center(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        print(Fore.CYAN + "║" + Fore.WHITE + f"  Domain: {target}".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        
        result = self.recon_scanner.scan_subdomains(target)
        self.results.append(result)
        
        subs = result.get('subdomains', [])
        if subs:
            print(Fore.CYAN + "║" + Fore.GREEN + Style.BRIGHT + f"  [+] Found {len(subs)} subdomains".ljust(68) + Fore.CYAN + "║")
            print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
            for s in subs[:15]:
                print(Fore.CYAN + "║  " + Fore.WHITE + f"→ {s}".ljust(66) + Fore.CYAN + "║")
        else:
            print(Fore.CYAN + "║" + Fore.YELLOW + "  [-] No subdomains found".ljust(68) + Fore.CYAN + "║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════════════╝")
        input(Fore.CYAN + "\n  Press Enter to continue...")
    
    def show_results(self):
        self.banner()
        if not self.results:
            print(Fore.YELLOW + "\n  [-] No results yet!")
            input(Fore.CYAN + "\n  Press Enter to continue...")
            return
        
        print(Fore.CYAN + "\n╔══════════════════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + Style.BRIGHT + "                    📊 SCAN RESULTS".center(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        print(Fore.CYAN + "║" + Fore.GREEN + Style.BRIGHT + f"  Total Scans: {len(self.results)}  |  Vulnerabilities: {self.vuln_count}".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        
        for i, res in enumerate(self.results, 1):
            target = res.get('target', 'Unknown')[:40]
            print(Fore.CYAN + f"║  " + Fore.WHITE + f"[{i}]".ljust(4) + Fore.CYAN + f"Target: " + Fore.WHITE + f"{target}".ljust(55) + Fore.CYAN + "║")
            
            if 'vulnerabilities' in res:
                count = len(res['vulnerabilities'])
                if count > 0:
                    print(Fore.CYAN + "║       " + Fore.RED + f"Vulnerabilities: {count}".ljust(60) + Fore.CYAN + "║")
            if 'open_ports' in res:
                count = len(res['open_ports'])
                if count > 0:
                    print(Fore.CYAN + "║       " + Fore.GREEN + f"Open Ports: {count}".ljust(60) + Fore.CYAN + "║")
            if 'subdomains' in res:
                count = len(res['subdomains'])
                if count > 0:
                    print(Fore.CYAN + "║       " + Fore.CYAN + f"Subdomains: {count}".ljust(60) + Fore.CYAN + "║")
            
            if i < len(self.results):
                print(Fore.CYAN + "║" + " " * 68 + Fore.CYAN + "║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════════════╝")
        input(Fore.CYAN + "\n  Press Enter to continue...")
    
    def generate_report(self):
        self.banner()
        if not self.results:
            print(Fore.YELLOW + "\n  [-] No results to report!")
            input(Fore.CYAN + "\n  Press Enter to continue...")
            return
        
        print(Fore.CYAN + "\n╔══════════════════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + Style.BRIGHT + "                    📄 REPORT GENERATOR".center(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        print(Fore.CYAN + "║" + Fore.WHITE + "  Available Formats:".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "║" + Fore.GREEN + "  [1] HTML  - Beautiful web report".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "║" + Fore.GREEN + "  [2] TXT   - Plain text report".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "║" + Fore.GREEN + "  [3] PDF   - Professional PDF".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "║" + Fore.GREEN + "  [4] JSON  - Raw JSON data".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "║" + Fore.GREEN + "  [5] All   - Generate all formats".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════════════╝")
        
        choice = input(Fore.YELLOW + "\n  Select format: " + Fore.WHITE)
        
        formats = []
        if choice == '1':
            formats = ['html']
        elif choice == '2':
            formats = ['txt']
        elif choice == '3':
            formats = ['pdf']
        elif choice == '4':
            formats = ['json']
        elif choice == '5':
            formats = ['html', 'txt', 'pdf', 'json']
        else:
            print(Fore.RED + "  [!] Invalid choice!")
            time.sleep(1)
            return
        
        os.makedirs("output/reports", exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        print(Fore.CYAN + "\n╔══════════════════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + Style.BRIGHT + "                    📊 GENERATING REPORTS".center(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        
        for fmt in formats:
            try:
                filename = f"output/reports/redhawk_report_{timestamp}.{fmt}"
                if fmt == 'html':
                    self._generate_html_report(filename)
                elif fmt == 'txt':
                    self._generate_txt_report(filename)
                elif fmt == 'json':
                    self._generate_json_report(filename)
                elif fmt == 'pdf':
                    self._generate_json_report(filename.replace('.pdf', '.json'))
                    print(Fore.CYAN + "║" + Fore.YELLOW + "  [i] PDF requires wkhtmltopdf".ljust(68) + Fore.CYAN + "║")
                
                print(Fore.CYAN + "║  " + Fore.GREEN + f"[+] {fmt.upper()} saved: {filename}".ljust(66) + Fore.CYAN + "║")
            except Exception as e:
                print(Fore.CYAN + "║  " + Fore.RED + f"[-] Failed: {fmt} - {e}".ljust(66) + Fore.CYAN + "║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════════════╝")
        input(Fore.CYAN + "\n  Press Enter to continue...")
    
    def _generate_json_report(self, filename):
        with open(filename, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'total_scans': len(self.results),
                'total_vulnerabilities': self.vuln_count,
                'results': self.results
            }, f, indent=2)
    
    def _generate_txt_report(self, filename):
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("REDHAWK SECURITY ASSESSMENT REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Scans: {len(self.results)}\n")
            f.write(f"Total Vulnerabilities: {self.vuln_count}\n\n")
            f.write("=" * 80 + "\n\n")
            
            for i, res in enumerate(self.results, 1):
                f.write(f"[{i}] TARGET: {res.get('target', 'Unknown')}\n")
                f.write("-" * 60 + "\n")
                
                if 'vulnerabilities' in res:
                    vulns = res['vulnerabilities']
                    if vulns:
                        f.write(f"Vulnerabilities Found: {len(vulns)}\n")
                        for v in vulns:
                            f.write(f"  • {v.get('type', 'Unknown')} [{v.get('severity', 'N/A')}]\n")
                            if v.get('details'):
                                f.write(f"    → {v['details']}\n")
                    else:
                        f.write("No vulnerabilities found\n")
                
                if 'open_ports' in res:
                    ports = res['open_ports']
                    if ports:
                        f.write(f"Open Ports: {len(ports)}\n")
                        for p in ports:
                            f.write(f"  • {p['port']} ({p['service']})\n")
                
                if 'subdomains' in res:
                    subs = res['subdomains']
                    if subs:
                        f.write(f"Subdomains: {len(subs)}\n")
                        for s in subs[:10]:
                            f.write(f"  • {s}\n")
                
                f.write("\n")
    
    def _generate_html_report(self, filename):
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>RedHawk Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #0a0e17; color: #e0e0e0; padding: 30px; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        .header {{ text-align: center; padding: 30px; border-bottom: 2px solid #ff3333; }}
        .header h1 {{ color: #ff3333; font-size: 40px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 15px; margin: 20px 0; }}
        .card {{ background: #1a1f2e; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #ff3333; }}
        .card .num {{ font-size: 28px; font-weight: bold; color: #ff3333; }}
        .card .label {{ color: #888; font-size: 12px; }}
        .section {{ background: #1a1f2e; border-radius: 8px; padding: 20px; margin: 15px 0; }}
        .section h2 {{ color: #ffaa00; border-bottom: 1px solid #2a2f3e; padding-bottom: 10px; }}
        .vuln {{ background: #0a0e17; padding: 12px; border-radius: 6px; margin: 8px 0; border-left: 4px solid #ff3333; }}
        .vuln .type {{ color: #ff3333; font-weight: bold; }}
        .vuln .sev {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; margin-left: 10px; }}
        .sev-critical {{ background: #ff3333; color: #fff; }}
        .sev-high {{ background: #ff6b00; color: #fff; }}
        .sev-medium {{ background: #ffaa00; color: #000; }}
        .sev-low {{ background: #00cc66; color: #000; }}
        .badge {{ background: #2a2f3e; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin: 2px; }}
        .footer {{ text-align: center; padding: 20px; border-top: 1px solid #2a2f3e; margin-top: 30px; color: #555; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔴 RedHawk</h1>
            <p style="color:#ffaa00;">Security Assessment Report</p>
            <p style="color:#888;font-size:14px;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <div class="card"><div class="num">{len(self.results)}</div><div class="label">Total Scans</div></div>
            <div class="card"><div class="num">{self.vuln_count}</div><div class="label">Vulnerabilities</div></div>
        </div>
"""
        
        for res in self.results:
            target = res.get('target', 'Unknown')
            vulns = res.get('vulnerabilities', [])
            
            html += f"""
        <div class="section">
            <h2>🎯 {target}</h2>
"""
            
            if vulns:
                html += f"<p style='color:#ff3333;'>⚠️ {len(vulns)} vulnerabilities found</p>"
                for v in vulns[:10]:
                    sev = v.get('severity', 'Medium').lower()
                    html += f"""
            <div class="vuln">
                <span class="type">{v.get('type', 'Unknown')}</span>
                <span class="sev sev-{sev}">{v.get('severity', 'N/A')}</span>
                <div style="color:#aaa;font-size:13px;margin-top:5px;">{v.get('details', v.get('payload', ''))}</div>
            </div>
"""
            else:
                html += "<p style='color:#00cc66;'>✅ No vulnerabilities found</p>"
            
            if res.get('directories'):
                html += f"<p style='color:#00cc66;'>📁 Directories: {', '.join(res['directories'][:5])}</p>"
            
            if res.get('open_ports'):
                ports = ', '.join([f"{p['port']}({p['service']})" for p in res['open_ports'][:5]])
                html += f"<p style='color:#00cc66;'>🔌 Open Ports: {ports}</p>"
            
            html += "</div>"
        
        html += f"""
        <div class="footer">RedHawk v1.0.0 | Advanced scanner for PenTesting | Ethical Use Only</div>
    </div>
</body>
</html>
"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def settings_menu(self):
        self.banner()
        
        print(Fore.CYAN + "\n╔══════════════════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + Style.BRIGHT + "                    ⚙️ SETTINGS".center(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        print(Fore.CYAN + "║" + Fore.WHITE + f"  Threads: {self.config.get('scanner.threads', 50)}".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "║" + Fore.WHITE + f"  Timeout: {self.config.get('scanner.timeout', 10)}s".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════════════╣")
        print(Fore.CYAN + "║" + Fore.GREEN + "  [1] Change Threads".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "║" + Fore.GREEN + "  [2] Change Timeout".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "║" + Fore.GREEN + "  [3] Reset to Defaults".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "║" + Fore.GREEN + "  [4] Back to Menu".ljust(68) + Fore.CYAN + "║")
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════════════╝")
        
        choice = input(Fore.YELLOW + "\n  Select: " + Fore.WHITE)
        
        if choice == '1':
            val = input(Fore.YELLOW + "  Threads: " + Fore.WHITE)
            if val.isdigit():
                self.config.set('scanner.threads', int(val))
                print(Fore.GREEN + "  [+] Updated!")
        elif choice == '2':
            val = input(Fore.YELLOW + "  Timeout (seconds): " + Fore.WHITE)
            if val.isdigit():
                self.config.set('scanner.timeout', int(val))
                print(Fore.GREEN + "  [+] Updated!")
        elif choice == '3':
            self.config = Config()
            print(Fore.GREEN + "  [+] Reset to defaults!")
        elif choice == '4':
            return
        
        time.sleep(1)
    
    def run(self):
        while True:
            try:
                self.show_menu()
                choice = input(Fore.YELLOW + "\n  ┌─[RedHawk]\n  └──╼ $ " + Fore.WHITE)
                
                if choice == '1':
                    self.run_web_scanner()
                elif choice == '2':
                    self.run_port_scan()
                elif choice == '3':
                    self.run_subdomain()
                elif choice == '4':
                    self.show_results()
                elif choice == '5':
                    self.generate_report()
                elif choice == '6':
                    self.settings_menu()
                elif choice == '7':
                    self.results = []
                    self.vuln_count = 0
                    print(Fore.GREEN + "\n  [+] Results cleared!")
                    time.sleep(1)
                elif choice == '0':
                    print(Fore.GREEN + "\n  [+] Stay lucky! 🦅")
                    sys.exit(0)
                else:
                    print(Fore.RED + "\n  [!] Invalid option!")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n  [!] Interrupted")
                sys.exit(0)
            except Exception as e:
                print(Fore.RED + f"\n  [!] Error: {e}")
                time.sleep(2)

if __name__ == "__main__":
    if os.name == 'posix' and os.geteuid() != 0:
        print(Fore.YELLOW + "  ⚠️  Some features require root privileges")
    
    hawk = RedHawk()
    hawk.run()