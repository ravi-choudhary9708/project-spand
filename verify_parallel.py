import requests
import time
import sys

BASE_URL = "http://localhost:8000"

def verify_parallel():
    # 1. Login
    print("Logging in...")
    try:
        res = requests.post(f"{BASE_URL}/api/auth/login", data={"username": "admin", "password": "admin123"})
        if res.status_code != 200:
            print(f"Login failed: {res.status_code} {res.text}")
            return
        
        token = res.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Trigger a scan with multiple domains to saturate the 5-worker thread pool
        targets = [
            "google.com", 
            "bing.com", 
            "duckduckgo.com", 
            "yahoo.com", 
            "wikipedia.org",
            "microsoft.com",
            "apple.com"
        ]
        
        print(f"Triggering scan for {len(targets)} domains...")
        payload = {
            "org_name": "Parallel Test Org",
            "target_assets": targets,
            "authorized": True
        }
        res = requests.post(f"{BASE_URL}/api/scans", headers=headers, json=payload)
        
        if res.status_code == 200:
            scan_data = res.json()
            scan_id = scan_data.get("scan_id")
            print(f"Scan created! ID: {scan_id}")
            print("Now checking logs for concurrent execution...")
            
            # Wait a few seconds for discovery to finish and parallel analysis to start
            time.sleep(10)
            
        else:
            print(f"Scan creation failed: {res.status_code} {res.text}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    verify_parallel()
