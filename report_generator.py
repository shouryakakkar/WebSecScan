import logging
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.units import inch

logger = logging.getLogger(__name__)

def generate_pdf_report(scan_data, output_file):
    """
    Generate a PDF report from scan data
    
    Args:
        scan_data (dict): Dictionary containing scan results
        output_file (str): Path to save the PDF report
    
    Returns:
        bool: True if report generation was successful, False otherwise
    """
    try:
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Create custom styles
        styles.add(ParagraphStyle(
            name='Title',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=12
        ))
        
        styles.add(ParagraphStyle(
            name='Heading2',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=8
        ))
        
        styles.add(ParagraphStyle(
            name='Heading3',
            parent=styles['Heading3'],
            fontSize=12,
            spaceAfter=6
        ))
        
        styles.add(ParagraphStyle(
            name='Normal',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=6
        ))
        
        styles.add(ParagraphStyle(
            name='Code',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            spaceAfter=6
        ))
        
        elements = []
        
        # Title page
        elements.append(Paragraph(f"Web Server Security Assessment Report", styles['Title']))
        elements.append(Spacer(1, 0.25*inch))
        elements.append(Paragraph(f"Target: {scan_data.get('target', 'Unknown')}", styles['Normal']))
        elements.append(Paragraph(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Paragraph(f"Scan ID: {scan_data.get('scan_id', 'Unknown')}", styles['Normal']))
        elements.append(Spacer(1, 0.5*inch))
        
        # Executive summary
        elements.append(Paragraph("Executive Summary", styles['Heading2']))
        summary = """
        This report presents the findings of an automated security assessment performed on the target web server.
        The assessment utilized Nmap for port and service scanning, and Nikto for web vulnerability discovery.
        Identified vulnerabilities were cross-referenced with the NIST National Vulnerability Database (NVD).
        
        This report outlines discovered open ports, running services, and potential security vulnerabilities,
        along with severity ratings and recommendations for remediation.
        """
        elements.append(Paragraph(summary, styles['Normal']))
        elements.append(Spacer(1, 0.25*inch))
        
        # Add page break before detailed results
        elements.append(PageBreak())
        
        # Nmap Scan Results
        elements.append(Paragraph("Port Scan Results", styles['Heading2']))
        nmap_results = scan_data.get('nmap_results', {})
        hosts = nmap_results.get('hosts', [])
        
        if not hosts:
            elements.append(Paragraph("No host information found.", styles['Normal']))
        else:
            for host_index, host in enumerate(hosts):
                host_addr = host.get('address', 'Unknown')
                hostname = host.get('hostname', 'Unknown')
                
                elements.append(Paragraph(f"Host {host_index+1}: {host_addr} ({hostname})", styles['Heading3']))
                
                # OS Information
                if 'os' in host:
                    os_info = host['os']
                    elements.append(Paragraph(f"Operating System: {os_info.get('name', 'Unknown')} "
                                            f"(Accuracy: {os_info.get('accuracy', 'Unknown')})", 
                                            styles['Normal']))
                
                # Port Information
                if 'ports' in host and host['ports']:
                    elements.append(Paragraph("Open Ports and Services:", styles['Normal']))
                    
                    # Create port table data
                    port_data = [['Port', 'Protocol', 'State', 'Service', 'Version']]
                    
                    for port in host['ports']:
                        port_id = port.get('port_id', 'Unknown')
                        protocol = port.get('protocol', 'Unknown')
                        state = port.get('state', 'Unknown')
                        
                        service_name = 'Unknown'
                        version = ''
                        
                        if 'service' in port:
                            service = port['service']
                            service_name = service.get('name', 'Unknown')
                            
                            version_parts = []
                            if 'product' in service:
                                version_parts.append(service['product'])
                            if 'version' in service:
                                version_parts.append(service['version'])
                            if 'extra_info' in service:
                                version_parts.append(f"({service['extra_info']})")
                                
                            version = ' '.join(version_parts)
                        
                        port_data.append([port_id, protocol, state, service_name, version])
                    
                    # Create and style the table
                    port_table = Table(port_data, colWidths=[0.5*inch, 0.7*inch, 0.7*inch, 1*inch, 2.5*inch])
                    port_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    
                    elements.append(port_table)
                    elements.append(Spacer(1, 0.25*inch))
                else:
                    elements.append(Paragraph("No open ports detected.", styles['Normal']))
        
        elements.append(PageBreak())
        
        # Nikto Scan Results
        elements.append(Paragraph("Web Vulnerability Scan Results", styles['Heading2']))
        nikto_results = scan_data.get('nikto_results', [])
        
        if not nikto_results:
            elements.append(Paragraph("No web vulnerabilities found or scan was not successful.", styles['Normal']))
        else:
            # Create vulnerability table data
            vuln_data = [['ID', 'Severity', 'Description']]
            
            for finding in nikto_results:
                finding_id = finding.get('id', 'Unknown')
                severity = finding.get('severity', 'Informational')
                description = finding.get('description', 'No description')
                
                vuln_data.append([finding_id, severity, description])
            
            # Create and style the table
            vuln_table = Table(vuln_data, colWidths=[1*inch, 0.8*inch, 4*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                # Highlight severities with colors
                ('TEXTCOLOR', (1, 1), (1, -1), colors.black),
            ]))
            
            # Highlight severities with colors after initial setup
            for i in range(1, len(vuln_data)):
                severity = vuln_data[i][1]
                if severity == 'High':
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (1, i), (1, i), colors.pink)
                    ]))
                elif severity == 'Medium':
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (1, i), (1, i), colors.orange)
                    ]))
                elif severity == 'Low':
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (1, i), (1, i), colors.lightgreen)
                    ]))
            
            elements.append(vuln_table)
            elements.append(Spacer(1, 0.25*inch))
        
        elements.append(PageBreak())
        
        # NIST NVD Vulnerabilities
        elements.append(Paragraph("Vulnerability Details", styles['Heading2']))
        vulnerabilities = scan_data.get('vulnerabilities', {})
        
        if not vulnerabilities:
            elements.append(Paragraph("No specific vulnerabilities identified in the NIST National Vulnerability Database.", styles['Normal']))
        else:
            # Group vulnerabilities by severity
            high_vulns = []
            medium_vulns = []
            low_vulns = []
            other_vulns = []
            
            for cve_id, vuln in vulnerabilities.items():
                severity = vuln.get('severity', 'Unknown')
                if severity == 'HIGH' or severity == 'High':
                    high_vulns.append(vuln)
                elif severity == 'MEDIUM' or severity == 'Medium':
                    medium_vulns.append(vuln)
                elif severity == 'LOW' or severity == 'Low':
                    low_vulns.append(vuln)
                else:
                    other_vulns.append(vuln)
                    
            # Sort each group by CVSS score (descending)
            def sort_by_cvss(vuln):
                try:
                    score = vuln.get('cvss_score', '0')
                    return float(score) if score != 'N/A' else 0
                except:
                    return 0
                    
            high_vulns.sort(key=sort_by_cvss, reverse=True)
            medium_vulns.sort(key=sort_by_cvss, reverse=True)
            low_vulns.sort(key=sort_by_cvss, reverse=True)
            
            all_vulns = high_vulns + medium_vulns + low_vulns + other_vulns
            
            for vuln in all_vulns:
                cve_id = vuln.get('id', 'Unknown')
                severity = vuln.get('severity', 'Unknown')
                cvss_score = vuln.get('cvss_score', 'N/A')
                description = vuln.get('description', 'No description available')
                published_date = vuln.get('published_date', 'Unknown')
                
                # Convert severity to color
                severity_color = colors.black
                if severity == 'HIGH' or severity == 'High':
                    severity_color = colors.red
                elif severity == 'MEDIUM' or severity == 'Medium':
                    severity_color = colors.orange
                elif severity == 'LOW' or severity == 'Low':
                    severity_color = colors.green
                
                # Create vulnerability header
                elements.append(Paragraph(
                    f"<font color='blue'>{cve_id}</font> - "
                    f"<font color='{severity_color}'>{severity}</font> "
                    f"(CVSS: {cvss_score})", 
                    styles['Heading3']))
                
                # Published date
                elements.append(Paragraph(f"Published: {published_date}", styles['Normal']))
                
                # Description
                elements.append(Paragraph("Description:", styles['Normal']))
                elements.append(Paragraph(description, styles['Normal']))
                
                # References
                references = vuln.get('references', [])
                if references:
                    elements.append(Paragraph("References:", styles['Normal']))
                    for ref in references[:5]:  # Limit to first 5 references
                        url = ref.get('url', '#')
                        name = ref.get('name', url)
                        source = ref.get('source', 'Unknown')
                        
                        elements.append(Paragraph(
                            f"• <font color='blue'>{name}</font> ({source})", 
                            styles['Normal']))
                
                elements.append(Spacer(1, 0.25*inch))
        
        elements.append(PageBreak())
        
        # Recommendations section
        elements.append(Paragraph("Recommendations", styles['Heading2']))
        
        # General recommendations
        general_recommendations = [
            "Keep all software up-to-date with the latest security patches",
            "Implement proper network segmentation to limit access to sensitive systems",
            "Use strong password policies and consider multi-factor authentication",
            "Monitor system logs for suspicious activities",
            "Regularly perform security scans and penetration testing",
            "Follow the principle of least privilege for user access"
        ]
        
        elements.append(Paragraph("General Security Recommendations:", styles['Heading3']))
        for rec in general_recommendations:
            elements.append(Paragraph(f"• {rec}", styles['Normal']))
        
        elements.append(Spacer(1, 0.25*inch))
        
        # Specific recommendations based on findings
        elements.append(Paragraph("Specific Recommendations Based on Findings:", styles['Heading3']))
        
        # Extract vulnerabilities by type for targeted recommendations
        has_http_vulns = False
        has_ssl_vulns = False
        has_outdated_software = False
        has_default_configs = False
        
        # Check Nikto results
        for finding in scan_data.get('nikto_results', []):
            desc = finding.get('description', '').lower()
            if any(term in desc for term in ['http', 'apache', 'nginx', 'iis']):
                has_http_vulns = True
            if any(term in desc for term in ['ssl', 'tls', 'certificate']):
                has_ssl_vulns = True
            if 'default' in desc or 'configuration' in desc:
                has_default_configs = True
                
        # Check Nmap results for outdated software
        for host in scan_data.get('nmap_results', {}).get('hosts', []):
            for port in host.get('ports', []):
                if 'service' in port and 'version' in port['service']:
                    # Simple heuristic to detect old versions
                    # This is just a placeholder - in real system would need better version checking
                    has_outdated_software = True
                    break
        
        # Add specific recommendations based on findings
        if has_http_vulns:
            elements.append(Paragraph("• Configure web servers with secure headers including Content-Security-Policy, X-XSS-Protection, and X-Content-Type-Options", styles['Normal']))
            elements.append(Paragraph("• Remove unnecessary HTTP methods and disable directory listing", styles['Normal']))
            elements.append(Paragraph("• Implement proper input validation for all web applications", styles['Normal']))
            
        if has_ssl_vulns:
            elements.append(Paragraph("• Upgrade to TLS 1.2 or 1.3 and disable older protocols (SSL 2.0/3.0, TLS 1.0/1.1)", styles['Normal']))
            elements.append(Paragraph("• Use strong cipher suites and enable Perfect Forward Secrecy", styles['Normal']))
            elements.append(Paragraph("• Ensure SSL/TLS certificates are valid and properly configured", styles['Normal']))
            
        if has_outdated_software:
            elements.append(Paragraph("• Update all server software to the latest stable versions", styles['Normal']))
            elements.append(Paragraph("• Implement a patch management system to automate updates", styles['Normal']))
            elements.append(Paragraph("• Consider using containerization to ease updates and deployment", styles['Normal']))
            
        if has_default_configs:
            elements.append(Paragraph("• Replace default configurations with hardened security settings", styles['Normal']))
            elements.append(Paragraph("• Remove default accounts, pages, and sample configurations", styles['Normal']))
            elements.append(Paragraph("• Use security benchmarks like CIS or NIST guidelines for configuration", styles['Normal']))
            
        # If no specific issues identified, add general web server hardening tips
        if not (has_http_vulns or has_ssl_vulns or has_outdated_software or has_default_configs):
            elements.append(Paragraph("• Implement a Web Application Firewall (WAF) to filter malicious traffic", styles['Normal']))
            elements.append(Paragraph("• Use Content Security Policy (CSP) headers to prevent XSS attacks", styles['Normal']))
            elements.append(Paragraph("• Enable HTTPS across all web services with proper certificate configuration", styles['Normal']))
            elements.append(Paragraph("• Implement rate limiting to prevent brute force and DoS attacks", styles['Normal']))
            
        # Add prioritization guidance
        elements.append(Spacer(1, 0.25*inch))
        elements.append(Paragraph("Prioritization Guidance:", styles['Heading3']))
        elements.append(Paragraph("1. Address high severity vulnerabilities immediately", styles['Normal']))
        elements.append(Paragraph("2. Fix medium severity issues within the next update cycle", styles['Normal']))
        elements.append(Paragraph("3. Schedule low severity findings for future maintenance", styles['Normal']))
        elements.append(Paragraph("4. Implement general security best practices as part of ongoing maintenance", styles['Normal']))
        
        # Build the PDF document
        doc.build(elements)
        
        logger.info(f"PDF report successfully generated: {output_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}", exc_info=True)
        return False
