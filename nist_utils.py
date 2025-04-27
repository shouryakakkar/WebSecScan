import requests
import logging
import time
import json
import re

logger = logging.getLogger(__name__)

def lookup_vulnerabilities(services, cves):
    """
    Look up vulnerabilities in NIST NVD database
    
    Args:
        services (list): List of service objects with product and version information
        cves (list): List of CVE IDs found during scans
        
    Returns:
        dict: Dictionary mapping CVE IDs to vulnerability information
    """
    vulnerabilities = {}
    
    # First, lookup CVEs explicitly found during scans
    for cve_id in cves:
        cve_info = lookup_cve(cve_id)
        if cve_info:
            vulnerabilities[cve_id] = cve_info
    
    # Then, lookup vulnerabilities for detected services
    for service in services:
        # Skip services without product info
        if not service.get('product'):
            continue
            
        service_vulns = lookup_service_vulnerabilities(
            service.get('product', ''),
            service.get('version', ''),
            service.get('name', '')
        )
        
        # Add service vulnerabilities to the overall dict
        for cve_id, cve_info in service_vulns.items():
            if cve_id not in vulnerabilities:
                vulnerabilities[cve_id] = cve_info
    
    return vulnerabilities

def lookup_cve(cve_id):
    """
    Look up a specific CVE in the NIST NVD database
    
    Args:
        cve_id (str): CVE ID (e.g., 'CVE-2021-12345')
        
    Returns:
        dict: CVE information including severity, description, and references
    """
    try:
        # Clean the CVE ID (sometimes it has extra text)
        cve_id = cve_id.strip()
        if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
            # Try to extract a CVE pattern
            match = re.search(r'(CVE-\d{4}-\d+)', cve_id)
            if match:
                cve_id = match.group(1)
            else:
                logger.warning(f"Invalid CVE ID format: {cve_id}")
                return None
        
        # Use NIST NVD API to fetch CVE information
        url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
        
        response = requests.get(url, timeout=10)
        
        # Add a small delay to avoid rate limiting
        time.sleep(0.6)
        
        if response.status_code != 200:
            logger.warning(f"Failed to retrieve CVE info for {cve_id}: HTTP {response.status_code}")
            return None
            
        data = response.json()
        
        # Check if the CVE data exists
        if 'result' not in data or 'CVE_Items' not in data['result']:
            logger.warning(f"No data found for CVE {cve_id}")
            return None
            
        cve_item = data['result']['CVE_Items'][0]
        
        # Extract basic information
        cve_data = {
            'id': cve_id,
            'description': 'No description available',
            'severity': 'Unknown',
            'cvss_score': 'N/A',
            'published_date': cve_item.get('publishedDate', 'Unknown'),
            'last_modified': cve_item.get('lastModifiedDate', 'Unknown'),
            'references': []
        }
        
        # Extract description
        if 'cve' in cve_item and 'description' in cve_item['cve']:
            desc_data = cve_item['cve']['description']['description_data']
            for desc in desc_data:
                if desc.get('lang') == 'en':
                    cve_data['description'] = desc.get('value', 'No description available')
                    break
        
        # Extract CVSS score and severity
        if 'impact' in cve_item:
            if 'baseMetricV3' in cve_item['impact']:
                cvss_data = cve_item['impact']['baseMetricV3']
                cve_data['cvss_score'] = cvss_data.get('cvssV3', {}).get('baseScore', 'N/A')
                cve_data['severity'] = cvss_data.get('cvssV3', {}).get('baseSeverity', 'Unknown')
            elif 'baseMetricV2' in cve_item['impact']:
                cvss_data = cve_item['impact']['baseMetricV2']
                cve_data['cvss_score'] = cvss_data.get('cvssV2', {}).get('baseScore', 'N/A')
                severity_score = float(cve_data['cvss_score']) if cve_data['cvss_score'] != 'N/A' else 0
                
                # Derive severity from CVSS v2 score
                if severity_score >= 7.0:
                    cve_data['severity'] = 'High'
                elif severity_score >= 4.0:
                    cve_data['severity'] = 'Medium'
                else:
                    cve_data['severity'] = 'Low'
        
        # Extract references
        if 'cve' in cve_item and 'references' in cve_item['cve']:
            refs_data = cve_item['cve']['references']['reference_data']
            for ref in refs_data:
                reference = {
                    'url': ref.get('url', ''),
                    'name': ref.get('name', ''),
                    'source': ref.get('refsource', '')
                }
                cve_data['references'].append(reference)
        
        return cve_data
        
    except Exception as e:
        logger.error(f"Error looking up CVE {cve_id}: {str(e)}", exc_info=True)
        return None

def lookup_service_vulnerabilities(product, version, service_name):
    """
    Look up vulnerabilities for a specific service based on product and version
    
    Args:
        product (str): Product name (e.g., 'Apache')
        version (str): Product version (e.g., '2.4.29')
        service_name (str): Service name (e.g., 'http')
        
    Returns:
        dict: Dictionary mapping CVE IDs to vulnerability information
    """
    vulnerabilities = {}
    
    try:
        # Skip lookup if product is empty
        if not product:
            return vulnerabilities
            
        # Construct search parameters
        search_term = product
        if version:
            search_term += f" {version}"
            
        # Use NIST NVD API to search for related vulnerabilities
        # Limiting to a reasonable number of results
        url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        params = {
            'keyword': search_term,
            'resultsPerPage': 10  # Limited to avoid overwhelming the API
        }
        
        response = requests.get(url, params=params, timeout=10)
        
        # Add a small delay to avoid rate limiting
        time.sleep(0.6)
        
        if response.status_code != 200:
            logger.warning(f"Failed to search vulnerabilities for {product} {version}: HTTP {response.status_code}")
            return vulnerabilities
            
        data = response.json()
        
        # Check if there are results
        if 'result' not in data or 'CVE_Items' not in data['result']:
            logger.info(f"No vulnerabilities found for {product} {version}")
            return vulnerabilities
            
        # Process each vulnerability
        for cve_item in data['result']['CVE_Items']:
            # Extract CVE ID
            cve_id = cve_item['cve']['CVE_data_meta']['ID']
            
            # Create basic vulnerability information
            vulnerability = {
                'id': cve_id,
                'description': 'No description available',
                'severity': 'Unknown',
                'cvss_score': 'N/A',
                'published_date': cve_item.get('publishedDate', 'Unknown'),
                'last_modified': cve_item.get('lastModifiedDate', 'Unknown'),
                'references': []
            }
            
            # Extract description
            if 'description' in cve_item['cve']:
                desc_data = cve_item['cve']['description']['description_data']
                for desc in desc_data:
                    if desc.get('lang') == 'en':
                        vulnerability['description'] = desc.get('value', 'No description available')
                        break
                        
            # Extract CVSS score and severity
            if 'impact' in cve_item:
                if 'baseMetricV3' in cve_item['impact']:
                    cvss_data = cve_item['impact']['baseMetricV3']
                    vulnerability['cvss_score'] = cvss_data.get('cvssV3', {}).get('baseScore', 'N/A')
                    vulnerability['severity'] = cvss_data.get('cvssV3', {}).get('baseSeverity', 'Unknown')
                elif 'baseMetricV2' in cve_item['impact']:
                    cvss_data = cve_item['impact']['baseMetricV2']
                    vulnerability['cvss_score'] = cvss_data.get('cvssV2', {}).get('baseScore', 'N/A')
                    severity_score = float(vulnerability['cvss_score']) if vulnerability['cvss_score'] != 'N/A' else 0
                    
                    # Derive severity from CVSS v2 score
                    if severity_score >= 7.0:
                        vulnerability['severity'] = 'High'
                    elif severity_score >= 4.0:
                        vulnerability['severity'] = 'Medium'
                    else:
                        vulnerability['severity'] = 'Low'
            
            # Extract references
            if 'references' in cve_item['cve']:
                refs_data = cve_item['cve']['references']['reference_data']
                for ref in refs_data:
                    reference = {
                        'url': ref.get('url', ''),
                        'name': ref.get('name', ''),
                        'source': ref.get('refsource', '')
                    }
                    vulnerability['references'].append(reference)
            
            # Add to vulnerabilities dict
            vulnerabilities[cve_id] = vulnerability
    
    except Exception as e:
        logger.error(f"Error looking up vulnerabilities for {product} {version}: {str(e)}", exc_info=True)
    
    return vulnerabilities
