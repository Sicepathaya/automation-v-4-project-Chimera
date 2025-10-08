# file: checkers/ctx.py

import requests

API_KEY = "CD17100C826742BD9F70656003DD57367EE8B297E0B7492BB8CD6303B3BDB415"

def check_ctx(hash_value):
    """Mendapatkan status dari CTX.io dan mengembalikannya."""
    url = f"https://api.ctx.io/v1/file/report/{hash_value}"
    headers = {"x-api-key": API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status() # Akan error jika status code 4xx atau 5xx
        data = response.json()
        
        detect = data.get("ctx_data", {}).get("detect")
        status = "Malicious" if detect else "Normal"
        return f"{status} {detect if detect else 'None'}"
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
    except Exception as e:
        return "Not Found or Error"