from flask import Flask, render_template, request, jsonify
import time
from typing import List, Dict, Optional
import re
import subprocess
import requests
from security_headers import analyze_headers
from zapv2 import ZAPv2
import nmap
app = Flask(__name__)


class VulnerabilityScanner:
    def __init__(self):
        self.zap = ZAPv2(apikey='your-api-key', proxies={'http': 'http://localhost:8080'})
    
    def scan_website(self, url: str) -> List[Dict[str, str]]:
        """Perform actual security scans"""
        vulnerabilities = []
        
        # 1. Check security headers
        vulnerabilities.extend(self.check_security_headers(url))
        
        # 2. SQL Injection scan (using sqlmap API)
        vulnerabilities.extend(self.sql_injection_scan(url))
        
        # 3. XSS scan (using OWASP ZAP)
        vulnerabilities.extend(self.xss_scan(url))
        
        # 4. Port/service scan (using nmap)
        vulnerabilities.extend(self.port_scan(url))
        
        return vulnerabilities

    def check_security_headers(self, url: str) -> List[Dict[str, str]]:
        """Analyze security headers"""
        try:
            response = requests.get(url, timeout=10)
            results = analyze_headers(response.headers)
            
            vulns = []
            for header, status in results.items():
                if status == "MISSING":
                    vulns.append({
                        'type': 'Security Headers',
                        'severity': 'Medium',
                        'description': f'Missing security header: {header}',
                        'recommendation': f'Configure the {header} header properly'
                    })
            return vulns
            
        except Exception as e:
            return [{
                'type': 'Connection Error',
                'severity': 'High',
                'description': f'Failed to connect to {url}: {str(e)}',
                'recommendation': 'Check if the URL is correct and accessible'
            }]

    def sql_injection_scan(self, url: str) -> List[Dict[str, str]]:
        """Run sqlmap scan"""
        try:
            # Start sqlmap API server first: sqlmapapi.py -s
            result = subprocess.run([
                'sqlmap',
                '-u', f"{url}?id=1",
                '--batch',
                '--risk=3',
                '--level=5',
                '--output-dir=./sqlmap_results'
            ], capture_output=True, text=True)
            
            vulns = []
            if "SQL injection" in result.stdout:
                vulns.append({
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'description': 'SQL injection vulnerability detected',
                    'recommendation': 'Use parameterized queries and input validation'
                })
            return vulns
            
        except Exception as e:
            return [{
                'type': 'Scan Error',
                'severity': 'Medium',
                'description': f'SQL injection scan failed: {str(e)}',
                'recommendation': 'Check sqlmap installation and try again'
            }]

    def xss_scan(self, url: str) -> List[Dict[str, str]]:
        """Use OWASP ZAP for XSS scanning"""
        try:
            scan_id = self.zap.spider.scan(url)
            while int(self.zap.spider.status(scan_id)) < 100:
                time.sleep(1)
            
            self.zap.active_scan.scan(url)
            alerts = self.zap.core.alerts()
            
            vulns = []
            for alert in alerts:
                if 'XSS' in alert.get('alert', ''):
                    vulns.append({
                        'type': 'XSS',
                        'severity': 'High',
                        'description': alert.get('description', 'XSS vulnerability found'),
                        'recommendation': 'Implement output encoding and CSP headers'
                    })
            return vulns
            
        except Exception as e:
            return [{
                'type': 'Scan Error',
                'severity': 'Medium',
                'description': f'XSS scan failed: {str(e)}',
                'recommendation': 'Ensure ZAP is running and configured properly'
            }]

    def port_scan(self, url: str) -> List[Dict[str, str]]:
        """Scan for open ports and services"""
        try:
            domain = url.split('//')[-1].split('/')[0]
            nm = nmap.PortScanner()
            nm.scan(hosts=domain, arguments='-sV')
            
            vulns = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        if port in [21, 22, 3389] and nm[host][proto][port]['state'] == 'open':
                            vulns.append({
                                'type': 'Open Port',
                                'severity': 'Medium',
                                'description': f'Potentially risky port {port}/{proto} is open',
                                'recommendation': f'Close port {port} if not needed'
                            })
            return vulns
            
        except Exception as e:
            return [{
                'type': 'Scan Error',
                'severity': 'Low',
                'description': f'Port scan failed: {str(e)}',
                'recommendation': 'Check nmap installation and permissions'
            }]


@app.route('/')
def home():
    return render_template('scanner.html')
    
@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url', '').strip()
    if not url:
        return jsonify({'error': 'Please enter a URL'}), 400
    
    # Validate URL format
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        requests.get(url, timeout=5)
    except:
        return jsonify({'error': 'Invalid or unreachable URL'}), 400
    
    scanner = VulnerabilityScanner()
    try:
        vulnerabilities = scanner.scan_website(url)
        return jsonify({
            'vulnerabilities': vulnerabilities,
            'count': len(vulnerabilities)
        })
    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500