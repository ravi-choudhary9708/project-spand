import requests
import os
import json
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("HUGGINGFACE_API_KEY")
# MODELS_TO_TEST = [
#     "mistralai/Mistral-7B-Instruct-v0.2",
#     "mistralai/Mistral-7B-Instruct-v0.3",
#     "Qwen/Qwen2.5-7B-Instruct",
#     "google/gemma-2-9b-it",
#     "microsoft/Phi-3-mini-4k-instruct"
# ]

MODEL_URL = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2"

def test_model(url, key):
    print(f"\nTesting Model: {url}")
    headers = {"Authorization": f"Bearer {key}"}
    payload = {
        "inputs": "[INST] Respond with ONLY the word 'CONNECTED' if you receive this. [/INST]",
        "parameters": {"max_new_tokens": 10}
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            print(f"Response: {response.json()}")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Exception: {e}")

if __name__ == "__main__":
    if not API_KEY:
        print("ERROR: HUGGINGFACE_API_KEY not found in .env")
    else:
        test_model(MODEL_URL, API_KEY)
        # test_model("https://api-inference.huggingface.co/models/microsoft/Phi-3-mini-4k-instruct", API_KEY)
        test_model("https://api-inference.huggingface.co/models/google/gemma-2-9b-it", API_KEY)
