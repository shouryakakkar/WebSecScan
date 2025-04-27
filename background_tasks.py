import threading
import logging
import os
from datetime import datetime
from scan_utils import run_nmap_scan, run_nikto_scan, parse_nmap_results, parse_nikto_results
from nist_utils import lookup_vulnerabilities
from report_generator import generate_pdf_report

# Configure logging
logger = logging.getLogger(__name__)

# Dictionary to store scan results
# Key: scan_id, Value: dict containing scan status, results, etc.
scan_results = {}

def run_scan_task(scan_id, target, scan_dir):
    """
    Background task to run scans and process results
    
    Args:
        scan_id (str): Unique ID for the scan
        target (str): Target URL or IP address
        scan_dir (str): Directory to store scan results
    """
    try:
        # Update scan status
        scan_results[scan_id] = {
            'status': 'in_progress',
            'target': target,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'message': 'Scan started',
            'progress': 10
        }
        
        # Run Nmap scan
        nmap_xml_file = os.path.join(scan_dir, 'nmap_results.xml')
        logger.debug(f"Starting Nmap scan on {target}")
        
        # Update status
        scan_results[scan_id]['message'] = 'Running Nmap scan...'
        scan_results[scan_id]['progress'] = 20
        
        nmap_success = run_nmap_scan(target, nmap_xml_file)
        
        if not nmap_success:
            scan_results[scan_id]['status'] = 'failed'
            scan_results[scan_id]['message'] = 'Nmap scan failed'
            return
            
        # Parse Nmap results
        nmap_results = parse_nmap_results(nmap_xml_file)
        
        # Update status
        scan_results[scan_id]['message'] = 'Nmap scan completed, running Nikto scan...'
        scan_results[scan_id]['progress'] = 40
        
        # Run Nikto scan
        nikto_output_file = os.path.join(scan_dir, 'nikto_results.txt')
        logger.debug(f"Starting Nikto scan on {target}")
        nikto_success = run_nikto_scan(target, nikto_output_file)
        
        # Parse Nikto results
        nikto_results = parse_nikto_results(nikto_output_file) if nikto_success else []
        
        # Update status
        scan_results[scan_id]['message'] = 'Processing results and looking up vulnerabilities...'
        scan_results[scan_id]['progress'] = 60
        
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
        
        # Update status
        scan_results[scan_id]['message'] = 'Generating report...'
        scan_results[scan_id]['progress'] = 80
        
        # Organize data for display and reporting
        scan_data = {
            'scan_id': scan_id,
            'target': target,
            'timestamp': scan_results[scan_id]['timestamp'],
            'nmap_results': nmap_results,
            'nikto_results': nikto_results,
            'vulnerabilities': vulnerability_data,
            'scan_dir': scan_dir
        }
        
        # Generate PDF report
        report_file = os.path.join(scan_dir, 'security_report.pdf')
        generate_pdf_report(scan_data, report_file)
        
        # Update status
        scan_results[scan_id]['status'] = 'completed'
        scan_results[scan_id]['message'] = 'Scan completed successfully'
        scan_results[scan_id]['progress'] = 100
        scan_results[scan_id]['data'] = scan_data
        
    except Exception as e:
        logger.error(f"Error during scan task: {str(e)}", exc_info=True)
        scan_results[scan_id]['status'] = 'failed'
        scan_results[scan_id]['message'] = f'Error during scan: {str(e)}'

def start_scan(scan_id, target, scan_dir):
    """
    Start a scan in a background thread
    
    Args:
        scan_id (str): Unique ID for the scan
        target (str): Target URL or IP address
        scan_dir (str): Directory to store scan results
    """
    thread = threading.Thread(target=run_scan_task, args=(scan_id, target, scan_dir))
    thread.daemon = True
    thread.start()
    
    return {
        'scan_id': scan_id,
        'status': 'initiated',
        'message': 'Scan initiated'
    }

def get_scan_status(scan_id):
    """
    Get the status of a scan
    
    Args:
        scan_id (str): Unique ID for the scan
        
    Returns:
        dict: Scan status information
    """
    return scan_results.get(scan_id, {
        'status': 'not_found',
        'message': 'Scan not found'
    })

def get_scan_results(scan_id):
    """
    Get the results of a completed scan
    
    Args:
        scan_id (str): Unique ID for the scan
        
    Returns:
        dict: Scan results or None if scan is not complete
    """
    if scan_id in scan_results and scan_results[scan_id].get('status') == 'completed':
        return scan_results[scan_id].get('data')
    return None