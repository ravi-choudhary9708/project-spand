import requests
import json

BASE_URL = "http://localhost:8000"

def verify():
    res = requests.post(f"{BASE_URL}/api/auth/login", data={"username": "admin", "password": "admin123"})
    token = res.json().get("access_token")
    
    res = requests.get(f"{BASE_URL}/api/scans/6231a7a9-4472-497d-8c4b-6c849ef770dd", headers={"Authorization": f"Bearer {token}"})
    print(res.text)

if __name__ == "__main__":
    verify()
