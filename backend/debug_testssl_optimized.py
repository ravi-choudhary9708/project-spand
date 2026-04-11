import sys
import os
import logging
import json

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from app.scanning.scanner import scan_asset

# Setup logging
logging.basicConfig(level=logging.INFO)

def test_scan(domain):
    print(f"--- Starting Optimized Scan for {domain} ---")
    import time
    start = time.time()
    result = scan_asset(domain)
    duration = time.time() - start
    print(f"--- Scan Finished in {duration:.2f} seconds ---")
    
    # Check for crucial data
    print(f"Protocol: {result.get('protocol')}")
    print(f"Open Ports: {[p['port'] for p in result.get('open_ports', [])]}")
    print(f"Certs found: {len(result.get('certificates', []))}")
    print(f"Ciphers found: {len(result.get('cipher_suites', []))}")
    
    # Check if testssl was used
    tls_data = result.get('tls_data', {})
    print(f"Primary Scan Method: {tls_data.get('scan_method')}")
    
    if result.get('certificates'):
        print(f"First Cert Algo: {result['certificates'][0].get('algorithm')}")
        print(f"First Cert Key Size: {result['certificates'][0].get('key_size')}")

if __name__ == "__main__":
    target = "google.com"  # Quick test
    if len(sys.argv) > 1:
        target = sys.argv[1]
    test_scan(target)
