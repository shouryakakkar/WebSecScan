import subprocess
import logging
import os
import xml.etree.ElementTree as ET
import re

logger = logging.getLogger(__name__)

def run_nmap_scan(target, output_file):
    """
    Run an Nmap scan on the target and save results to XML file
    
    Args:
        target (str): Target URL or IP address
        output_file (str): Path to save XML output
        
    Returns:
        bool: True if scan completed successfully, False otherwise
    """
    try:
        # Command to run comprehensive Nmap scan
        # -sV: Service/version detection
        # -sT: TCP connect scan (doesn't require root)
        # -O: OS detection (might be limited without root)
        # -oX: Output to XML
        command = [
            'nmap', '-sV', '-sT', '-O', 
            '--script', 'default,safe,vuln', 
            '-oX', output_file, 
            target
        ]
        
        logger.debug(f"Running Nmap command: {' '.join(command)}")
        
        # Run the Nmap command
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            logger.error(f"Nmap scan failed with return code {process.returncode}")
            logger.error(f"Stderr: {stderr}")
            return False
            
        if not os.path.exists(output_file):
            logger.error("Nmap output file was not created")
            return False
            
        logger.debug("Nmap scan completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error running Nmap scan: {str(e)}", exc_info=True)
        return False

def run_nikto_scan(target, output_file):
    """
    Run a Nikto scan on the target and save results to a text file
    
    Args:
        target (str): Target URL or IP address
        output_file (str): Path to save text output
        
    Returns:
        bool: True if scan completed successfully, False otherwise
    """
    try:
        # Ensure target has a protocol
        if not target.startswith('http://') and not target.startswith('https://'):
            target = 'http://' + target
            
        # Command to run Nikto scan
        # Using a more basic scan for reliability
        # -h: Target host
        # -o: Output file
        # -Format: Output format
        # -Tuning: Scan tuning (1: Interesting files, 2: Misconfiguration, 3: Information disclosure, 4: Injection)
        # -Display: Customize display output
        command = [
            'nikto', '-h', target, 
            '-o', output_file, 
            '-Format', 'txt',
            '-Tuning', '1234',
            '-Display', 'V',
            '-timeout', '30'
        ]
        
        logger.debug(f"Running Nikto command: {' '.join(command)}")
        
        # Run the Nikto command
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            logger.error(f"Nikto scan failed with return code {process.returncode}")
            logger.error(f"Stderr: {stderr}")
            # Still continue, as Nikto sometimes returns non-zero even with partial results
            
        if not os.path.exists(output_file):
            logger.error("Nikto output file was not created")
            return False
            
        logger.debug("Nikto scan completed")
        return True
        
    except Exception as e:
        logger.error(f"Error running Nikto scan: {str(e)}", exc_info=True)
        return False

def parse_nmap_results(xml_file):
    """
    Parse Nmap XML output file and return structured data
    
    Args:
        xml_file (str): Path to Nmap XML output file
        
    Returns:
        dict: Structured Nmap scan results
    """
    try:
        if not os.path.exists(xml_file):
            logger.error(f"Nmap XML file not found: {xml_file}")
            return {"hosts": []}
            
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        result = {
            "hosts": []
        }
        
        # Add scan info
        scan_info = root.find('scaninfo')
        if scan_info is not None:
            result['scan_info'] = dict(scan_info.attrib)
            
        # Process each host
        for host in root.findall('host'):
            host_data = {"ports": []}
            
            # Get address
            address = host.find('address')
            if address is not None:
                host_data['address'] = address.attrib.get('addr', 'unknown')
                host_data['address_type'] = address.attrib.get('addrtype', 'unknown')
            
            # Get hostname
            hostnames = host.find('hostnames')
            if hostnames is not None:
                hostname = hostnames.find('hostname')
                if hostname is not None:
                    host_data['hostname'] = hostname.attrib.get('name', 'unknown')
            
            # Get OS detection
            os_elem = host.find('os')
            if os_elem is not None:
                os_match = os_elem.find('osmatch')
                if os_match is not None:
                    host_data['os'] = {
                        'name': os_match.attrib.get('name', 'unknown'),
                        'accuracy': os_match.attrib.get('accuracy', 'unknown')
                    }
            
            # Get ports and services
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port in ports_elem.findall('port'):
                    port_data = {
                        'protocol': port.attrib.get('protocol', 'unknown'),
                        'port_id': port.attrib.get('portid', 'unknown')
                    }
                    
                    # Get port state
                    state = port.find('state')
                    if state is not None:
                        port_data['state'] = state.attrib.get('state', 'unknown')
                    
                    # Get service info
                    service = port.find('service')
                    if service is not None:
                        service_data = {
                            'name': service.attrib.get('name', 'unknown'),
                        }
                        
                        if 'product' in service.attrib:
                            service_data['product'] = service.attrib['product']
                        
                        if 'version' in service.attrib:
                            service_data['version'] = service.attrib['version']
                        
                        if 'extrainfo' in service.attrib:
                            service_data['extra_info'] = service.attrib['extrainfo']
                            
                        port_data['service'] = service_data
                    
                    # Get script results (vulnerability scan)
                    scripts = []
                    for script in port.findall('script'):
                        script_data = {
                            'id': script.attrib.get('id', 'unknown'),
                            'output': script.attrib.get('output', '')
                        }
                        scripts.append(script_data)
                    
                    if scripts:
                        port_data['scripts'] = scripts
                    
                    host_data['ports'].append(port_data)
            
            result['hosts'].append(host_data)
            
        return result
        
    except Exception as e:
        logger.error(f"Error parsing Nmap results: {str(e)}", exc_info=True)
        return {"hosts": []}

def parse_nikto_results(txt_file):
    """
    Parse Nikto text output file and return structured data
    
    Args:
        txt_file (str): Path to Nikto text output file
        
    Returns:
        list: List of vulnerability findings
    """
    try:
        if not os.path.exists(txt_file):
            logger.error(f"Nikto text file not found: {txt_file}")
            return []
            
        findings = []
        with open(txt_file, 'r') as f:
            content = f.read()
            
        # Extract scan target and date
        scan_info = {}
        target_match = re.search(r'- Target: (.*)', content)
        if target_match:
            scan_info['target'] = target_match.group(1).strip()
            
        date_match = re.search(r'- Start Time: (.*)', content)
        if date_match:
            scan_info['date'] = date_match.group(1).strip()
        
        # Extract each finding line
        # Nikto format typically has lines like: "+ OSVDB-3092: /admin/: This might be interesting..."
        finding_pattern = r'\+ (.*?): (.*)'
        matches = re.findall(finding_pattern, content)
        
        for match in matches:
            finding_id = match[0].strip()
            description = match[1].strip()
            
            finding = {
                'id': finding_id,
                'description': description
            }
            
            # Try to determine severity based on content
            severity = "Informational"
            if "Cross Site Scripting" in description or "XSS" in description:
                severity = "High"
            elif "SQL Injection" in description or "SQLi" in description:
                severity = "High"
            elif "CVE-" in description:
                severity = "Medium"  # Default for CVEs unless more info is available
            elif "vulnerability" in description.lower():
                severity = "Medium"
            elif "warning" in description.lower():
                severity = "Low"
                
            finding['severity'] = severity
            findings.append(finding)
            
        return findings
        
    except Exception as e:
        logger.error(f"Error parsing Nikto results: {str(e)}", exc_info=True)
        return []
