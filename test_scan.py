import requests
import sys

BASE_URL = "http://localhost:8000"

def test_scan():
    # 1. Login to get token
    print("Logging in...")
    try:
        res = requests.post(f"{BASE_URL}/api/auth/login", data={"username": "admin", "password": "admin123"})
        if res.status_code != 200:
            print(f"Login failed: {res.status_code} {res.text}")
            return
        
        token = res.json().get("access_token")
        print("Login successful.")

        # 2. Create scan
        print("Creating scan...")
        headers = {"Authorization": f"Bearer {token}"}
        payload = {
            "org_name": "Test Org",
            "target_assets": ["google.com"],
            "authorized": True
        }
        res = requests.post(f"{BASE_URL}/api/scans", headers=headers, json=payload)
        
        if res.status_code == 200:
            print("Scan created successfully!")
            print(res.json())
        else:
            print(f"Scan creation failed: {res.status_code}")
            print(res.text)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_scan()
