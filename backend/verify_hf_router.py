import requests
import os
import json
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("HUGGINGFACE_API_KEY")
# The new unified router endpoint
ROUTER_URL = "https://router.huggingface.co/hf-inference/v1/chat/completions"

def test_router(model, key):
    print(f"\nTesting Router with Model: {model}")
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": "Respond with ONLY the word 'CONNECTED' if you receive this."}
        ],
        "max_tokens": 10
    }
    
    try:
        response = requests.post(ROUTER_URL, headers=headers, json=payload, timeout=20)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Response: {data['choices'][0]['message']['content']}")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Exception: {e}")

if __name__ == "__main__":
    if not API_KEY:
        print("ERROR: HUGGINGFACE_API_KEY not found in .env")
    else:
        # Testing a few common models on the router
        test_router("meta-llama/Meta-Llama-3-8B-Instruct", API_KEY)
        test_router("mistralai/Mistral-7B-Instruct-v0.3", API_KEY)
        test_router("google/gemma-2-9b-it", API_KEY)
