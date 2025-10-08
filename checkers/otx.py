# file: checkers/otx.py

import requests

def check_otx(hash_value):
    """Mendapatkan skor dari OTX AlienVault."""
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}/analysis"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            # Pulses adalah indikator ancaman di OTX
            pulses = data.get("general", {}).get("pulse_info", {}).get("count", 0)
            return f"{pulses} pulses"
        elif r.status_code == 404:
            return "Not Found"
        else:
            return f"Error: HTTP {r.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"