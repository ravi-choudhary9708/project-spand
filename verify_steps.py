import requests
import json

BASE_URL = "http://localhost:8000"

def verify():
    print("Logging in...")
    res = requests.post(f"{BASE_URL}/api/auth/login", data={"username": "admin", "password": "admin123"})
    token = res.json().get("access_token")
    
    print("Fetching scans...")
    res = requests.get(f"{BASE_URL}/api/scans", headers={"Authorization": f"Bearer {token}"})
    scans = res.json()
    
    for scan in scans:
        if scan['status'] == 'RUNNING':
            print(f"Scan ID: {scan['scan_id']}")
            print(f"Database Progress: {scan['progress']}%")
            
            # Direct check if possible
            from celery.result import AsyncResult
            from app.celery_app import celery_app
            
            # Since this runs inside backend, we can access celery_app
            res_celery = AsyncResult(scan['scan_id'], app=celery_app) # Wait, scan_id is not task_id
            # I need the celery_task_id which is in the DB
    
    # Let's hit the backend endpoint for a specific scan
    for scan in scans:
        if scan['status'] == 'RUNNING':
            print(f"Checking scan via API: {scan['scan_id']}")
            res = requests.get(f"{BASE_URL}/api/scans/{scan['scan_id']}", headers={"Authorization": f"Bearer {token}"})
            print(f"API Response: {res.json()}")
            print("-" * 20)

if __name__ == "__main__":
    verify()
