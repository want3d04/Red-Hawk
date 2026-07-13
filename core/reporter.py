#!/usr/bin/env python3
# core/reporter.py - Report Generator (HTML, TXT, PDF, JSON)

import os
import json
from datetime import datetime
from typing import Dict, Any, List

class Reporter:
    """Generate reports in multiple formats"""
    
    def __init__(self):
        self.report_dir = "output/reports"
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate(self, results: List[Dict], format: str = "html") -> str:
        """Generate report in specified format"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.report_dir}/redhawk_report_{timestamp}"
        
        if format == "html":
            return self._generate_html(results, filename)
        elif format == "txt":
            return self._generate_txt(results, filename)
        elif format == "pdf":
            return self._generate_pdf(results, filename)
        elif format == "json":
            return self._generate_json(results, filename)
        else:
            return self._generate_html(results, filename)
    
    def _generate_html(self, results: List[Dict], filename: str) -> str:
        """Generate HTML report"""
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedHawk Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e17; color: #e0e0e0; padding: 40px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ text-align: center; padding: 40px 0; border-bottom: 2px solid #ff3333; }}
        .header h1 {{ color: #ff3333; font-size: 48px; letter-spacing: 4px; }}
        .header .subtitle {{ color: #ffaa00; font-size: 18px; margin-top: 10px; }}
        .header .meta {{ color: #888; font-size: 14px; margin-top: 15px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 30px 0; }}
        .summary-card {{ background: #1a1f2e; padding: 20px; border-radius: 10px; text-align: center; border-left: 4px solid #ff3333; }}
        .summary-card .number {{ font-size: 36px; font-weight: bold; color: #ff3333; }}
        .summary-card .label {{ color: #888; font-size: 14px; margin-top: 5px; }}
        .section {{ background: #1a1f2e; border-radius: 10px; padding: 25px; margin: 20px 0; }}
        .section h2 {{ color: #ffaa00; border-bottom: 1px solid #2a2f3e; padding-bottom: 10px; margin-bottom: 20px; }}
        .vuln-item {{ background: #0a0e17; padding: 15px; border-radius: 8px; margin: 10px 0; border-left: 4px solid #ff3333; }}
        .vuln-item .type {{ color: #ff3333; font-weight: bold; }}
        .vuln-item .severity {{ display: inline-block; padding: 2px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; margin-left: 10px; }}
        .severity-critical {{ background: #ff3333; color: #fff; }}
        .severity-high {{ background: #ff6b00; color: #fff; }}
        .severity-medium {{ background: #ffaa00; color: #000; }}
        .severity-low {{ background: #00cc66; color: #000; }}
        .vuln-item .details {{ color: #aaa; font-size: 14px; margin-top: 5px; }}
        .footer {{ text-align: center; padding: 20px 0; border-top: 1px solid #2a2f3e; margin-top: 40px; color: #555; font-size: 12px; }}
        .badge {{ display: inline-block; background: #2a2f3e; padding: 2px 10px; border-radius: 4px; font-size: 12px; margin: 2px; }}
        @media (max-width: 768px) {{
            .summary {{ grid-template-columns: 1fr 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔴 RedHawk</h1>
            <div class="subtitle">Security Assessment Report</div>
            <div class="meta">
                Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &bull; 
                Scans: {len(results)} &bull; 
                Vulnerabilities: {self._count_vulns(results)}
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="number">{len(results)}</div>
                <div class="label">Total Scans</div>
            </div>
            <div class="summary-card">
                <div class="number">{self._count_vulns(results)}</div>
                <div class="label">Vulnerabilities</div>
            </div>
            <div class="summary-card">
                <div class="number">{self._count_by_severity(results, 'Critical')}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card">
                <div class="number">{self._count_by_severity(results, 'High')}</div>
                <div class="label">High</div>
            </div>
        </div>
"""
        
        for result in results:
            target = result.get('target', 'Unknown')
            vulns = result.get('vulnerabilities', [])
            
            html_content += f"""
        <div class="section">
            <h2>🎯 Target: {target}</h2>
"""
            
            if result.get('info', {}).get('technologies'):
                tech = ', '.join(result['info']['technologies'])
                html_content += f"""
            <div style="margin-bottom: 15px;">
                <span class="badge">🛠️ {tech}</span>
            </div>
"""
            
            if vulns:
                html_content += f"""
            <div style="margin-bottom: 15px; color: #ff3333; font-weight: bold;">
                ⚠️ {len(vulns)} vulnerabilities found
            </div>
"""
                for v in vulns[:10]:
                    sev = v.get('severity', 'Medium')
                    sev_class = f"severity-{sev.lower()}"
                    html_content += f"""
            <div class="vuln-item">
                <span class="type">{v.get('type', 'Unknown')}</span>
                <span class="severity {sev_class}">{sev}</span>
                <div class="details">
                    {v.get('details', v.get('payload', 'No details'))}
                    {f"<br>Parameter: {v.get('parameter', '')}" if v.get('parameter') else ''}
                </div>
            </div>
"""
            else:
                html_content += """
            <div style="color: #00cc66; font-weight: bold;">✅ No vulnerabilities found</div>
"""
            
            if result.get('directories'):
                dirs = ', '.join(result['directories'][:10])
                html_content += f"""
            <div style="margin-top: 15px; color: #00cc66;">
                📁 Directories: {dirs}{'...' if len(result['directories']) > 10 else ''}
            </div>
"""
            
            if result.get('open_ports'):
                ports = ', '.join([f"{p['port']}({p['service']})" for p in result['open_ports'][:10]])
                html_content += f"""
            <div style="margin-top: 15px; color: #00cc66;">
                🔌 Open Ports: {ports}{'...' if len(result['open_ports']) > 10 else ''}
            </div>
"""
            
            if result.get('subdomains'):
                subs = ', '.join(result['subdomains'][:10])
                html_content += f"""
            <div style="margin-top: 15px; color: #00cc66;">
                🌐 Subdomains: {subs}{'...' if len(result['subdomains']) > 10 else ''}
            </div>
"""
            
            html_content += """
        </div>
"""
        
        html_content += f"""
        <div class="footer">
            RedHawk v1.0.0 &bull; Advanced Scanner tool for PenTesting &bull; Ethical Use Only
        </div>
    </div>
</body>
</html>
"""
        
        filename_html = f"{filename}.html"
        with open(filename_html, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filename_html
    
    def _generate_txt(self, results: List[Dict], filename: str) -> str:
        """Generate TXT report"""
        content = []
        content.append("=" * 80)
        content.append("🔴 RedHawk Security Assessment Report")
        content.append("=" * 80)
        content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content.append(f"Total Scans: {len(results)}")
        content.append(f"Total Vulnerabilities: {self._count_vulns(results)}")
        content.append("=" * 80)
        content.append("")
        
        for i, result in enumerate(results, 1):
            target = result.get('target', 'Unknown')
            vulns = result.get('vulnerabilities', [])
            content.append(f"\n[{i}] TARGET: {target}")
            content.append("-" * 60)
            
            if result.get('info', {}).get('technologies'):
                content.append(f"Technologies: {', '.join(result['info']['technologies'])}")
            
            if vulns:
                content.append(f"\n⚠️ Vulnerabilities Found: {len(vulns)}")
                for v in vulns:
                    sev = v.get('severity', 'Medium')
                    content.append(f"  • {v.get('type', 'Unknown')} [{sev}]")
                    if v.get('details'):
                        content.append(f"    → {v['details']}")
                    if v.get('parameter'):
                        content.append(f"    → Parameter: {v['parameter']}")
            else:
                content.append("\n✅ No vulnerabilities found")
            
            if result.get('directories'):
                content.append(f"\n📁 Directories: {len(result['directories'])}")
                for d in result['directories'][:10]:
                    content.append(f"  • {d}")
            
            if result.get('open_ports'):
                content.append(f"\n🔌 Open Ports: {len(result['open_ports'])}")
                for p in result['open_ports'][:10]:
                    content.append(f"  • {p['port']} ({p['service']})")
            
            if result.get('subdomains'):
                content.append(f"\n🌐 Subdomains: {len(result['subdomains'])}")
                for s in result['subdomains'][:10]:
                    content.append(f"  • {s}")
        
        content.append("\n" + "=" * 80)
        content.append("RedHawk v3.0.0 | Advanced Penetration Testing Framework")
        content.append("=" * 80)
        
        filename_txt = f"{filename}.txt"
        with open(filename_txt, 'w', encoding='utf-8') as f:
            f.write('\n'.join(content))
        
        return filename_txt
    
    def _generate_pdf(self, results: List[Dict], filename: str) -> str:
        """Generate PDF report"""
        html_file = self._generate_html(results, filename)
        pdf_file = f"{filename}.pdf"
        
        try:
            import pdfkit
            pdfkit.from_file(html_file, pdf_file)
            return pdf_file
        except ImportError:
            print("[!] pdfkit not installed. Install with: pip install pdfkit")
            print("[!] Also install wkhtmltopdf: https://wkhtmltopdf.org/downloads.html")
            return html_file
        except Exception as e:
            print(f"[!] PDF generation failed: {e}")
            return html_file
    
    def _generate_json(self, results: List[Dict], filename: str) -> str:
        """Generate JSON report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_scans': len(results),
            'total_vulnerabilities': self._count_vulns(results),
            'scans': results
        }
        
        filename_json = f"{filename}.json"
        with open(filename_json, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filename_json
    
    def _count_vulns(self, results: List[Dict]) -> int:
        count = 0
        for r in results:
            count += len(r.get('vulnerabilities', []))
        return count
    
    def _count_by_severity(self, results: List[Dict], severity: str) -> int:
        count = 0
        for r in results:
            for v in r.get('vulnerabilities', []):
                if v.get('severity') == severity:
                    count += 1
        return count