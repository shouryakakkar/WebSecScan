import os
import logging
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, session
from scan_utils import run_nmap_scan, run_nikto_scan, parse_nmap_results, parse_nikto_results
from nist_utils import lookup_vulnerabilities
from report_generator import generate_pdf_report

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "websec_scanner_secret")

# Directory for storing scan results
SCAN_DIR = "scan_results"
if not os.path.exists(SCAN_DIR):
    os.makedirs(SCAN_DIR)

@app.route('/')
def index():
    """Render the main page with the scan form"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Handle scan requests and initiate the scanning process"""
    target = request.form.get('target', '').strip()
    
    if not target:
        flash('Please enter a valid target URL or IP address', 'danger')
        return redirect(url_for('index'))
    
    # Create a unique scan ID
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    scan_dir = os.path.join(SCAN_DIR, f"{scan_id}_{timestamp}")
    
    if not os.path.exists(scan_dir):
        os.makedirs(scan_dir)
    
    # Store the scan info in session
    session['scan_info'] = {
        'scan_id': scan_id,
        'target': target,
        'timestamp': timestamp,
        'scan_dir': scan_dir
    }
    
    try:
        # Run Nmap scan
        nmap_xml_file = os.path.join(scan_dir, 'nmap_results.xml')
        logger.debug(f"Starting Nmap scan on {target}")
        nmap_success = run_nmap_scan(target, nmap_xml_file)
        
        if not nmap_success:
            flash('Nmap scan failed. Please check the target and try again.', 'danger')
            return redirect(url_for('index'))
            
        # Parse Nmap results
        nmap_results = parse_nmap_results(nmap_xml_file)
        
        # Run Nikto scan
        nikto_output_file = os.path.join(scan_dir, 'nikto_results.txt')
        logger.debug(f"Starting Nikto scan on {target}")
        nikto_success = run_nikto_scan(target, nikto_output_file)
        
        if not nikto_success:
            flash('Nikto scan completed with errors.', 'warning')
        
        # Parse Nikto results
        nikto_results = parse_nikto_results(nikto_output_file) if nikto_success else []
        
        # Lookup vulnerabilities in NIST NVD
        logger.debug("Looking up vulnerabilities in NIST NVD")
        
        # Collect service information from Nmap results
        services = []
        for host in nmap_results.get('hosts', []):
            for port in host.get('ports', []):
                if 'service' in port and 'product' in port['service']:
                    services.append({
                        'product': port['service'].get('product', ''),
                        'version': port['service'].get('version', ''),
                        'name': port['service'].get('name', '')
                    })
        
        # Extract CVEs from Nikto results
        cves = []
        for item in nikto_results:
            if 'CVE' in item.get('description', ''):
                cve_ids = []
                for part in item.get('description', '').split():
                    if part.startswith('CVE-'):
                        cve_ids.append(part)
                for cve_id in cve_ids:
                    cves.append(cve_id)
        
        # Lookup vulnerabilities
        vulnerability_data = lookup_vulnerabilities(services, cves)
        
        # Organize data for display and reporting
        scan_data = {
            'scan_id': scan_id,
            'target': target,
            'timestamp': timestamp,
            'nmap_results': nmap_results,
            'nikto_results': nikto_results,
            'vulnerabilities': vulnerability_data,
            'scan_dir': scan_dir
        }
        
        # Generate PDF report
        report_file = os.path.join(scan_dir, 'security_report.pdf')
        generate_pdf_report(scan_data, report_file)
        
        # Store scan data in session for accessing in results page
        session['scan_data'] = scan_data
        
        return redirect(url_for('results', scan_id=scan_id))
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}", exc_info=True)
        flash(f'An error occurred during the scan: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/results/<scan_id>')
def results(scan_id):
    """Display scan results"""
    scan_data = session.get('scan_data', None)
    
    if not scan_data or scan_data['scan_id'] != scan_id:
        flash('Scan results not found or expired', 'danger')
        return redirect(url_for('index'))
    
    return render_template('results.html', scan_data=scan_data)

@app.route('/download_report/<scan_id>')
def download_report(scan_id):
    """Download the PDF report for a scan"""
    scan_data = session.get('scan_data', None)
    
    if not scan_data or scan_data['scan_id'] != scan_id:
        flash('Scan report not found or expired', 'danger')
        return redirect(url_for('index'))
    
    report_file = os.path.join(scan_data['scan_dir'], 'security_report.pdf')
    
    if not os.path.exists(report_file):
        flash('Report file not found', 'danger')
        return redirect(url_for('results', scan_id=scan_id))
    
    return send_file(report_file, as_attachment=True, download_name=f"security_report_{scan_id}.pdf")

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
