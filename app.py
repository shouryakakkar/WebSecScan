import os
import logging
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, session
from background_tasks import start_scan, get_scan_status, get_scan_results

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
        # Start the scan in a background thread
        logger.debug(f"Starting background scan for {target}")
        start_scan(scan_id, target, scan_dir)
        
        # Redirect to the status page
        return redirect(url_for('scan_status', scan_id=scan_id))
        
    except Exception as e:
        logger.error(f"Error initiating scan: {str(e)}", exc_info=True)
        flash(f'An error occurred while initiating the scan: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    """Display scan status and progress"""
    # Get scan info from session
    scan_info = session.get('scan_info', None)
    
    if not scan_info or scan_info['scan_id'] != scan_id:
        flash('Scan information not found', 'danger')
        return redirect(url_for('index'))
    
    return render_template('status.html', scan_info=scan_info)

@app.route('/api/scan_status/<scan_id>')
def api_scan_status(scan_id):
    """API endpoint for getting scan status"""
    status = get_scan_status(scan_id)
    return jsonify(status)

@app.route('/results/<scan_id>')
def results(scan_id):
    """Display scan results"""
    # Get scan results from background task
    scan_data = get_scan_results(scan_id)
    
    if not scan_data:
        # Check if scan is still in progress
        status = get_scan_status(scan_id)
        if status.get('status') == 'in_progress':
            # Redirect to status page
            return redirect(url_for('scan_status', scan_id=scan_id))
        else:
            flash('Scan results not found or scan failed', 'danger')
            return redirect(url_for('index'))
    
    # Store scan data in session for using in download
    session['scan_data'] = scan_data
    
    return render_template('results.html', scan_data=scan_data)

@app.route('/download_report/<scan_id>')
def download_report(scan_id):
    """Download the PDF report for a scan"""
    # First try to get from background tasks
    scan_data = get_scan_results(scan_id)
    
    # If not found, try from session (backward compatibility)
    if not scan_data:
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
