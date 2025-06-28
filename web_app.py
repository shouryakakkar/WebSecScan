import os
import logging
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, flash, redirect, url_for
from web_scanner import WebSecurityScanner
import json
import csv
from io import StringIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from io import BytesIO

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "websec_scanner_secret")

# Initialize scanner
scanner = WebSecurityScanner()

# In-memory storage for scan results (for demo purposes)
# In production, use a database
scan_results = {}

@app.route('/')
def index():
    """Render the main page with the scan form"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Handle scan requests and perform the scanning process"""
    target = request.form.get('target', '').strip()
    
    if not target:
        flash('Please enter a valid target URL', 'danger')
        return redirect(url_for('index'))
    
    # Create a unique scan ID
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    
    try:
        # Perform the scan
        logger.debug(f"Starting web security scan for {target}")
        results = scanner.scan_target(target)
        
        # Add scan metadata
        results['scan_id'] = scan_id
        results['timestamp'] = timestamp
        results['status'] = 'completed'
        
        # Store results
        scan_results[scan_id] = results
        
        # Store the scan info in session
        session['scan_info'] = {
            'scan_id': scan_id,
            'target': target,
            'timestamp': timestamp
        }
        
        # Redirect to results page
        return redirect(url_for('results', scan_id=scan_id))
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}", exc_info=True)
        flash(f'An error occurred during the scan: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/results/<scan_id>')
def results(scan_id):
    """Display scan results"""
    scan_data = scan_results.get(scan_id)
    
    if not scan_data:
        flash('Scan results not found or expired', 'danger')
        return redirect(url_for('index'))
    
    return render_template('web_results.html', scan_data=scan_data)

@app.route('/api/scan/<scan_id>')
def api_scan_results(scan_id):
    """API endpoint for getting scan results"""
    scan_data = scan_results.get(scan_id)
    
    if not scan_data:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_data)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for performing scans"""
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target URL is required'}), 400
    
    try:
        # Perform the scan
        results = scanner.scan_target(target)
        
        # Add scan metadata
        scan_id = str(uuid.uuid4())
        results['scan_id'] = scan_id
        results['timestamp'] = datetime.now().isoformat()
        results['status'] = 'completed'
        
        # Store results
        scan_results[scan_id] = results
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error during API scan: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/download/<scan_id>')
def download_results(scan_id):
    """Download scan results as JSON"""
    scan_data = scan_results.get(scan_id)
    
    if not scan_data:
        flash('Scan results not found or expired', 'danger')
        return redirect(url_for('index'))
    
    # Create JSON response
    response = app.response_class(
        response=json.dumps(scan_data, indent=2),
        status=200,
        mimetype='application/json'
    )
    response.headers['Content-Disposition'] = f'attachment; filename=security_scan_{scan_id}.json'
    return response

@app.route('/download_csv/<scan_id>')
def download_csv(scan_id):
    """Download scan results as CSV"""
    scan_data = scan_results.get(scan_id)
    
    if not scan_data:
        flash('Scan results not found or expired', 'danger')
        return redirect(url_for('index'))
    
    # Create CSV data
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Category', 'Item', 'Value', 'Status', 'Severity'])
    
    # Security Headers
    for header, value in scan_data.get('security_headers', {}).items():
        status = 'Present' if value != 'Not Set' else 'Missing'
        severity = 'High' if header in ['hsts', 'x_content_type_options'] else 'Medium'
        writer.writerow(['Security Headers', header.replace('_', '-').title(), value, status, severity])
    
    # SSL/TLS Info
    ssl_info = scan_data.get('ssl_info', {})
    if 'error' not in ssl_info and ssl_info:
        writer.writerow(['SSL/TLS', 'Version', ssl_info.get('version', 'N/A'), 'Present', 'Info'])
        writer.writerow(['SSL/TLS', 'Cipher', ssl_info.get('cipher', 'N/A'), 'Present', 'Info'])
        writer.writerow(['SSL/TLS', 'Expiry', ssl_info.get('cert_expiry', 'N/A'), 'Present', 'Info'])
    
    # Vulnerabilities
    for vuln in scan_data.get('vulnerabilities', []):
        writer.writerow(['Vulnerabilities', vuln['type'], vuln['description'], 'Found', vuln['severity']])
    
    # Information Disclosure
    for disclosure in scan_data.get('information_disclosure', []):
        writer.writerow(['Information Disclosure', disclosure['type'], disclosure['description'], 'Found', disclosure['severity']])
    
    # Technology Stack
    for tech in scan_data.get('technology_stack', []):
        writer.writerow(['Technology Stack', 'Technology', tech, 'Detected', 'Info'])
    
    # Open Ports
    for port in scan_data.get('open_ports', []):
        writer.writerow(['Open Ports', f"Port {port['port']}", port['service'], 'Open', 'Info'])
    
    # Recommendations
    for rec in scan_data.get('recommendations', []):
        writer.writerow(['Recommendations', rec['title'], rec['description'], 'Suggested', rec['severity']])
    
    # Create CSV response
    response = app.response_class(
        response=output.getvalue(),
        status=200,
        mimetype='text/csv'
    )
    response.headers['Content-Disposition'] = f'attachment; filename=security_scan_{scan_id}.csv'
    return response

@app.route('/download_pdf/<scan_id>')
def download_pdf(scan_id):
    """Download scan results as PDF"""
    scan_data = scan_results.get(scan_id)
    
    if not scan_data:
        flash('Scan results not found or expired', 'danger')
        return redirect(url_for('index'))
    
    # Create PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=30,
        alignment=1  # Center alignment
    )
    story.append(Paragraph(f"Security Scan Report - {scan_data['target']}", title_style))
    story.append(Spacer(1, 12))
    
    # Scan Information
    story.append(Paragraph("Scan Information", styles['Heading2']))
    story.append(Paragraph(f"<b>Target:</b> {scan_data['target']}", styles['Normal']))
    story.append(Paragraph(f"<b>Scan Time:</b> {scan_data['scan_time']}", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Security Headers
    story.append(Paragraph("Security Headers Analysis", styles['Heading2']))
    headers_data = [['Header', 'Value', 'Status']]
    for header, value in scan_data.get('security_headers', {}).items():
        status = 'Present' if value != 'Not Set' else 'Missing'
        headers_data.append([header.replace('_', '-').title(), value, status])
    
    headers_table = Table(headers_data, colWidths=[2*inch, 3*inch, 1*inch])
    headers_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(headers_table)
    story.append(Spacer(1, 12))
    
    # SSL/TLS Configuration
    ssl_info = scan_data.get('ssl_info', {})
    if 'error' not in ssl_info and ssl_info:
        story.append(Paragraph("SSL/TLS Configuration", styles['Heading2']))
        story.append(Paragraph(f"<b>Version:</b> {ssl_info.get('version', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"<b>Cipher:</b> {ssl_info.get('cipher', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"<b>Expires:</b> {ssl_info.get('cert_expiry', 'N/A')}", styles['Normal']))
        story.append(Spacer(1, 12))
    
    # Vulnerabilities
    vulnerabilities = scan_data.get('vulnerabilities', [])
    if vulnerabilities:
        story.append(Paragraph(f"Vulnerabilities Found ({len(vulnerabilities)})", styles['Heading2']))
        for vuln in vulnerabilities:
            story.append(Paragraph(f"<b>{vuln['type']}</b> - {vuln['description']}", styles['Normal']))
            story.append(Paragraph(f"Severity: {vuln['severity']}", styles['Normal']))
            story.append(Spacer(1, 6))
        story.append(Spacer(1, 12))
    
    # Information Disclosure
    disclosures = scan_data.get('information_disclosure', [])
    if disclosures:
        story.append(Paragraph(f"Information Disclosure ({len(disclosures)})", styles['Heading2']))
        for disclosure in disclosures:
            story.append(Paragraph(f"<b>{disclosure['type']}</b> - {disclosure['description']}", styles['Normal']))
            story.append(Paragraph(f"Severity: {disclosure['severity']}", styles['Normal']))
            story.append(Spacer(1, 6))
        story.append(Spacer(1, 12))
    
    # Technology Stack
    tech_stack = scan_data.get('technology_stack', [])
    if tech_stack:
        story.append(Paragraph("Technology Stack Detected", styles['Heading2']))
        story.append(Paragraph(", ".join(tech_stack), styles['Normal']))
        story.append(Spacer(1, 12))
    
    # Open Ports
    open_ports = scan_data.get('open_ports', [])
    if open_ports:
        story.append(Paragraph(f"Open Ports ({len(open_ports)})", styles['Heading2']))
        ports_data = [['Port', 'Service', 'Status']]
        for port in open_ports:
            ports_data.append([str(port['port']), port['service'], port['status']])
        
        ports_table = Table(ports_data, colWidths=[1*inch, 2*inch, 1*inch])
        ports_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(ports_table)
        story.append(Spacer(1, 12))
    
    # Recommendations
    recommendations = scan_data.get('recommendations', [])
    if recommendations:
        story.append(Paragraph(f"Security Recommendations ({len(recommendations)})", styles['Heading2']))
        for rec in recommendations:
            story.append(Paragraph(f"<b>{rec['title']}</b>", styles['Normal']))
            story.append(Paragraph(rec['description'], styles['Normal']))
            story.append(Paragraph(f"Category: {rec['category']} | Severity: {rec['severity']}", styles['Normal']))
            story.append(Spacer(1, 6))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    
    # Create PDF response
    response = app.response_class(
        response=buffer.getvalue(),
        status=200,
        mimetype='application/pdf'
    )
    response.headers['Content-Disposition'] = f'attachment; filename=security_scan_{scan_id}.pdf'
    return response

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('index.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors"""
    return render_template('index.html', error="Internal server error"), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True) 