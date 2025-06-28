import requests
import ssl
import socket
import re
import json
import logging
from urllib.parse import urlparse, urljoin
from datetime import datetime
import time

logger = logging.getLogger(__name__)

class WebSecurityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def scan_target(self, target):
        """
        Perform comprehensive web security scan
        
        Args:
            target (str): Target URL
            
        Returns:
            dict: Complete scan results
        """
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
            
        results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'security_headers': {},
            'ssl_info': {},
            'vulnerabilities': [],
            'information_disclosure': [],
            'technology_stack': [],
            'robots_txt': {},
            'sitemap': {},
            'open_ports': [],
            'recommendations': []
        }
        
        try:
            # Parse URL
            parsed_url = urlparse(target)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # 1. Security Headers Analysis
            results['security_headers'] = self.check_security_headers(target)
            
            # 2. SSL/TLS Configuration
            if parsed_url.scheme == 'https':
                results['ssl_info'] = self.check_ssl_configuration(parsed_url.netloc)
            
            # 3. Common Vulnerabilities
            results['vulnerabilities'] = self.check_common_vulnerabilities(target)
            
            # 4. Information Disclosure
            results['information_disclosure'] = self.check_information_disclosure(target)
            
            # 5. Technology Stack Detection
            results['technology_stack'] = self.detect_technology_stack(target)
            
            # 6. Robots.txt Analysis
            results['robots_txt'] = self.analyze_robots_txt(base_url)
            
            # 7. Sitemap Analysis
            results['sitemap'] = self.analyze_sitemap(base_url)
            
            # 8. Port Scanning (simulated)
            results['open_ports'] = self.simulate_port_scan(parsed_url.netloc)
            
            # 9. Generate Recommendations
            results['recommendations'] = self.generate_recommendations(results)
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            results['error'] = str(e)
            
        return results
    
    def check_security_headers(self, url):
        """Check security headers"""
        headers = {}
        try:
            response = self.session.get(url, timeout=10)
            headers = dict(response.headers)
            
            security_headers = {
                'hsts': headers.get('Strict-Transport-Security', 'Not Set'),
                'x_content_type_options': headers.get('X-Content-Type-Options', 'Not Set'),
                'x_frame_options': headers.get('X-Frame-Options', 'Not Set'),
                'x_xss_protection': headers.get('X-XSS-Protection', 'Not Set'),
                'content_security_policy': headers.get('Content-Security-Policy', 'Not Set'),
                'referrer_policy': headers.get('Referrer-Policy', 'Not Set'),
                'permissions_policy': headers.get('Permissions-Policy', 'Not Set'),
                'server': headers.get('Server', 'Not Set'),
                'x_powered_by': headers.get('X-Powered-By', 'Not Set')
            }
            
            return security_headers
            
        except Exception as e:
            logger.error(f"Error checking security headers: {str(e)}")
            return {'error': str(e)}
    
    def check_ssl_configuration(self, hostname):
        """Check SSL/TLS configuration"""
        ssl_info = {}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    ssl_info = {
                        'version': ssock.version(),
                        'cipher': cipher[0] if cipher else 'Unknown',
                        'cert_subject': dict(x[0] for x in cert['subject']),
                        'cert_issuer': dict(x[0] for x in cert['issuer']),
                        'cert_expiry': cert['notAfter'],
                        'cert_valid_from': cert['notBefore']
                    }
                    
        except Exception as e:
            logger.error(f"Error checking SSL: {str(e)}")
            ssl_info = {'error': str(e)}
            
        return ssl_info
    
    def check_common_vulnerabilities(self, url):
        """Check for common vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for directory traversal
            test_paths = ['../', '..\\', '%2e%2e%2f', '%2e%2e%5c']
            for path in test_paths:
                test_url = urljoin(url, path)
                try:
                    response = self.session.get(test_url, timeout=5)
                    if response.status_code == 200 and len(response.text) > 1000:
                        vulnerabilities.append({
                            'type': 'Directory Traversal',
                            'description': f'Potential directory traversal via {path}',
                            'severity': 'High',
                            'url': test_url
                        })
                except:
                    pass
            
            # Check for sensitive files
            sensitive_files = [
                '.env', 'config.php', 'wp-config.php', 'web.config',
                '.git/config', '.htaccess', 'robots.txt', 'sitemap.xml'
            ]
            
            for file in sensitive_files:
                test_url = urljoin(url, file)
                try:
                    response = self.session.get(test_url, timeout=5)
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Sensitive File Exposure',
                            'description': f'Sensitive file accessible: {file}',
                            'severity': 'Medium',
                            'url': test_url
                        })
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Error checking vulnerabilities: {str(e)}")
            
        return vulnerabilities
    
    def check_information_disclosure(self, url):
        """Check for information disclosure"""
        disclosures = []
        
        try:
            response = self.session.get(url, timeout=10)
            
            # Check for error messages
            error_patterns = [
                r'error in your SQL syntax',
                r'stack trace',
                r'debug information',
                r'php error',
                r'asp\.net error',
                r'java\.lang\.',
                r'python traceback'
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    disclosures.append({
                        'type': 'Error Information Disclosure',
                        'description': f'Error information found: {pattern}',
                        'severity': 'Medium'
                    })
            
            # Check for version information
            version_patterns = [
                r'apache/\d+\.\d+',
                r'nginx/\d+\.\d+',
                r'php/\d+\.\d+',
                r'asp\.net/\d+\.\d+',
                r'wordpress/\d+\.\d+'
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    disclosures.append({
                        'type': 'Version Information Disclosure',
                        'description': f'Version information found: {match.group()}',
                        'severity': 'Low'
                    })
                    
        except Exception as e:
            logger.error(f"Error checking information disclosure: {str(e)}")
            
        return disclosures
    
    def detect_technology_stack(self, url):
        """Detect technology stack"""
        technologies = []
        
        try:
            response = self.session.get(url, timeout=10)
            headers = dict(response.headers)
            content = response.text
            
            # Check headers for technology indicators
            if 'X-Powered-By' in headers:
                technologies.append(headers['X-Powered-By'])
            
            if 'Server' in headers:
                technologies.append(headers['Server'])
            
            # Check content for technology indicators
            tech_patterns = {
                'WordPress': r'wp-content|wp-includes|wordpress',
                'Drupal': r'drupal|drupal\.js',
                'Joomla': r'joomla|joomla\.js',
                'React': r'react|react\.js',
                'Angular': r'angular|ng-',
                'Vue.js': r'vue\.js|v-',
                'Bootstrap': r'bootstrap|bootstrap\.css',
                'jQuery': r'jquery|jquery\.js',
                'PHP': r'\.php|php',
                'ASP.NET': r'\.aspx|asp\.net',
                'Python': r'python|django|flask',
                'Node.js': r'node\.js|express'
            }
            
            for tech, pattern in tech_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    technologies.append(tech)
                    
        except Exception as e:
            logger.error(f"Error detecting technology stack: {str(e)}")
            
        return list(set(technologies))  # Remove duplicates
    
    def analyze_robots_txt(self, base_url):
        """Analyze robots.txt file"""
        robots_info = {}
        
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=5)
            
            if response.status_code == 200:
                robots_info = {
                    'exists': True,
                    'content': response.text,
                    'sitemap': None
                }
                
                # Extract sitemap URL
                sitemap_match = re.search(r'Sitemap:\s*(.+)', response.text, re.IGNORECASE)
                if sitemap_match:
                    robots_info['sitemap'] = sitemap_match.group(1).strip()
            else:
                robots_info = {'exists': False}
                
        except Exception as e:
            logger.error(f"Error analyzing robots.txt: {str(e)}")
            robots_info = {'exists': False, 'error': str(e)}
            
        return robots_info
    
    def analyze_sitemap(self, base_url):
        """Analyze sitemap"""
        sitemap_info = {}
        
        try:
            sitemap_url = urljoin(base_url, '/sitemap.xml')
            response = self.session.get(sitemap_url, timeout=5)
            
            if response.status_code == 200:
                sitemap_info = {
                    'exists': True,
                    'url_count': len(re.findall(r'<url>', response.text)),
                    'last_modified': None
                }
                
                # Extract last modified date
                lastmod_match = re.search(r'<lastmod>(.+)</lastmod>', response.text)
                if lastmod_match:
                    sitemap_info['last_modified'] = lastmod_match.group(1)
            else:
                sitemap_info = {'exists': False}
                
        except Exception as e:
            logger.error(f"Error analyzing sitemap: {str(e)}")
            sitemap_info = {'exists': False, 'error': str(e)}
            
        return sitemap_info
    
    def simulate_port_scan(self, hostname):
        """Simulate basic port scanning using common ports"""
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    service = self.get_service_name(port)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'status': 'open'
                    })
                sock.close()
            except:
                pass
                
        return open_ports
    
    def get_service_name(self, port):
        """Get service name for common ports"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')
    
    def generate_recommendations(self, results):
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        # Security Headers recommendations
        headers = results.get('security_headers', {})
        if headers.get('hsts') == 'Not Set':
            recommendations.append({
                'category': 'Security Headers',
                'title': 'Enable HSTS',
                'description': 'Implement HTTP Strict Transport Security to force HTTPS connections',
                'severity': 'High'
            })
        
        if headers.get('x_content_type_options') == 'Not Set':
            recommendations.append({
                'category': 'Security Headers',
                'title': 'Enable X-Content-Type-Options',
                'description': 'Add X-Content-Type-Options: nosniff header to prevent MIME type sniffing',
                'severity': 'Medium'
            })
        
        if headers.get('x_frame_options') == 'Not Set':
            recommendations.append({
                'category': 'Security Headers',
                'title': 'Enable X-Frame-Options',
                'description': 'Add X-Frame-Options header to prevent clickjacking attacks',
                'severity': 'Medium'
            })
        
        # SSL/TLS recommendations
        ssl_info = results.get('ssl_info', {})
        if 'error' not in ssl_info and ssl_info.get('version'):
            if 'TLSv1.0' in ssl_info['version'] or 'TLSv1.1' in ssl_info['version']:
                recommendations.append({
                    'category': 'SSL/TLS',
                    'title': 'Upgrade TLS Version',
                    'description': 'Disable TLS 1.0/1.1 and use TLS 1.2 or higher',
                    'severity': 'High'
                })
        
        # Vulnerability recommendations
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            recommendations.append({
                'category': 'Vulnerabilities',
                'title': 'Fix Identified Vulnerabilities',
                'description': f'Address {len(vulnerabilities)} identified security vulnerabilities',
                'severity': 'High'
            })
        
        return recommendations 