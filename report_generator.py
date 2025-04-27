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
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Use existing styles instead of redefining them
        title_style = styles['Title']
        heading2_style = styles['Heading2']
        heading3_style = styles['Heading3']
        normal_style = styles['Normal']
        
        # Create story (content) for the PDF
        story = []
        
        # Add title
        story.append(Paragraph("Security Scan Report", title_style))
        story.append(Spacer(1, 12))
        
        # Add scan information
        story.append(Paragraph("Scan Information", heading2_style))
        story.append(Spacer(1, 6))
        
        scan_info = [
            ["Target:", scan_data.get('target', 'N/A')],
            ["Scan ID:", scan_data.get('scan_id', 'N/A')],
            ["Date:", scan_data.get('timestamp', 'N/A')],
            ["Status:", scan_data.get('status', 'N/A')]
        ]
        
        info_table = Table(scan_info, colWidths=[100, 400])
        info_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(info_table)
        story.append(Spacer(1, 12))
        
        # Add vulnerability summary
        story.append(Paragraph("Vulnerability Summary", heading2_style))
        story.append(Spacer(1, 6))
        
        # Count vulnerabilities by severity
        severity_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        
        # Count from Nikto results
        if 'nikto_results' in scan_data:
            for finding in scan_data['nikto_results']:
                severity = finding.get('severity', 'Informational')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count from CVE results
        if 'vulnerabilities' in scan_data:
            for vuln in scan_data['vulnerabilities'].values():
                severity = vuln.get('severity', 'Informational')
                if severity.upper() == 'HIGH':
                    severity_counts['High'] += 1
                elif severity.upper() == 'MEDIUM':
                    severity_counts['Medium'] += 1
                elif severity.upper() == 'LOW':
                    severity_counts['Low'] += 1
                else:
                    severity_counts['Informational'] += 1
        
        # Create vulnerability summary table
        vuln_summary = [
            ["Severity", "Count"],
            ["High", str(severity_counts['High'])],
            ["Medium", str(severity_counts['Medium'])],
            ["Low", str(severity_counts['Low'])],
            ["Informational", str(severity_counts['Informational'])]
        ]
        
        vuln_table = Table(vuln_summary, colWidths=[200, 100])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
        story.append(vuln_table)
        story.append(Spacer(1, 12))
        
        # Add scan results
        story.append(Paragraph("Scan Results", heading2_style))
        story.append(Spacer(1, 6))
        
        # Add Nmap results if available
        if 'nmap_results' in scan_data and scan_data['nmap_results']:
            story.append(Paragraph("Nmap Scan Results", heading3_style))
            story.append(Spacer(1, 6))
            
            # Format Nmap results
            nmap_data = []
            for host in scan_data['nmap_results'].get('hosts', []):
                for port in host.get('ports', []):
                    service = port.get('service', {})
                    nmap_data.append([
                        Paragraph(str(port.get('port_id', 'N/A')), normal_style),
                        Paragraph(str(port.get('protocol', 'N/A')), normal_style),
                        Paragraph(str(port.get('state', 'N/A')), normal_style),
                        Paragraph(str(service.get('name', 'N/A')), normal_style),
                        Paragraph(str(service.get('product', 'N/A')), normal_style),
                        Paragraph(str(service.get('version', 'N/A')), normal_style)
                    ])
            
            if nmap_data:
                nmap_table = Table([["Port", "Protocol", "State", "Service", "Product", "Version"]] + nmap_data,
                                 colWidths=[50, 70, 70, 80, 100, 80])
                nmap_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(nmap_table)
                story.append(Spacer(1, 12))
        
        # Add Nikto results if available
        if 'nikto_results' in scan_data and scan_data['nikto_results']:
            story.append(Paragraph("Web Vulnerabilities", heading3_style))
            story.append(Spacer(1, 6))
            
            nikto_data = []
            for finding in scan_data['nikto_results']:
                nikto_data.append([
                    finding.get('id', 'N/A'),
                    finding.get('severity', 'N/A'),
                    Paragraph(finding.get('description', 'N/A'), normal_style)
                ])
            
            if nikto_data:
                nikto_table = Table([["ID", "Severity", "Description"]] + nikto_data,
                                  colWidths=[100, 100, 300])
                nikto_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(nikto_table)
                story.append(Spacer(1, 12))
        
        # Add CVE details if available
        if 'vulnerabilities' in scan_data and scan_data['vulnerabilities']:
            story.append(Paragraph("CVE Details", heading3_style))
            story.append(Spacer(1, 6))
            
            cve_data = []
            for cve_id, vuln in scan_data['vulnerabilities'].items():
                cve_data.append([
                    cve_id,
                    vuln.get('severity', 'N/A'),
                    vuln.get('cvss_score', 'N/A'),
                    Paragraph(vuln.get('description', 'N/A'), normal_style)
                ])
            
            if cve_data:
                cve_table = Table([["CVE ID", "Severity", "CVSS Score", "Description"]] + cve_data,
                                colWidths=[100, 80, 80, 240])
                cve_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(cve_table)
                story.append(Spacer(1, 12))
        
        # Add recommendations
        story.append(Paragraph("Recommendations", heading2_style))
        story.append(Spacer(1, 6))
        
        recommendations = [
            "Keep all software up-to-date with the latest security patches",
            "Implement proper network segmentation to limit access to sensitive systems",
            "Use strong password policies and consider multi-factor authentication",
            "Monitor system logs for suspicious activities",
            "Regularly perform security scans and penetration testing",
            "Follow the principle of least privilege for user access"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", normal_style))
            story.append(Spacer(1, 6))
        
        # Build the PDF
        doc.build(story)
        logger.info(f"PDF report generated successfully at {output_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}", exc_info=True)
        return False
