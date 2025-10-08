# file: checkers/virustotal.py

import vt
import time
import random
from itertools import cycle
from collections import deque

# --- KONFIGURASI ---
API_KEYS = [
    "fe35c7701ac38d24d4c735c3a072c3625bff9f908cddc25f2c3b6c2f54c284b4",
    "b3f10420878c46c7ddf87cee5f789924f75a9070386a8aec7c2f91aaff91e419"
    # Tambahkan API Key gratis lainnya di sini untuk meningkatkan throughput
    # "api_key_kedua_anda",
    # "api_key_ketiga_anda",
]
# Batas permintaan per menit untuk setiap API key gratis
MAX_REQUESTS_PER_MINUTE_PER_KEY = 4
MAX_RETRIES = 3

# --- MANAJEMEN STATE UNTUK RATE LIMITER ---
key_cycle = cycle(API_KEYS)
# Dictionary untuk menyimpan timestamp permintaan terakhir untuk setiap API key
# deque adalah list efisien untuk menambah/menghapus dari kedua ujung
api_request_times = {key: deque() for key in API_KEYS}


def check_virustotal(hash_value):
    """
    Mendapatkan skor dan family threat dari VirusTotal dengan rate limiter cerdas
    untuk menghindari ban sementara.
    """
    api_key = next(key_cycle)
    
    # --- LOGIKA RATE LIMITER CERDAS ---
    now = time.time()
    timestamps = api_request_times[api_key]

    # 1. Bersihkan timestamp lama yang sudah lebih dari 60 detik
    while timestamps and now - timestamps[0] > 60:
        timestamps.popleft()

    # 2. Cek apakah kita sudah mencapai limit untuk key ini
    if len(timestamps) >= MAX_REQUESTS_PER_MINUTE_PER_KEY:
        # Hitung berapa lama harus menunggu hingga timestamp terlama keluar dari jendela 60 detik
        oldest_timestamp = timestamps[0]
        wait_time = 60 - (now - oldest_timestamp) + 1 # +1 detik untuk keamanan
        
        if wait_time > 0:
            print(f"⏳ VT Rate limit tercapai untuk key {api_key[:4]}... Menunggu {wait_time:.1f} detik.")
            time.sleep(wait_time)
            
    # 4. Catat timestamp permintaan baru ini SEBELUM request dikirim
    api_request_times[api_key].append(time.time())
    # --- AKHIR LOGIKA RATE LIMITER ---

    for attempt in range(MAX_RETRIES):
        try:
            with vt.Client(api_key) as client:
                try:
                    obj = client.get_object(f"/files/{hash_value}")
                    stats = obj.last_analysis_stats
                    malicious = stats.get('malicious', 0)
                    total_verdicts = (
                        stats.get('malicious', 0) +
                        stats.get('suspicious', 0) +
                        stats.get('undetected', 0) +
                        stats.get('harmless', 0) 
                    )
                    
                    if total_verdicts == 0:
                        total_verdicts = sum(stats.values())
                    
                    score_str = f"{malicious}/{total_verdicts}"
                    threat_label = ""

                    if hasattr(obj, 'popular_threat_classification'):
                        label_info = obj.popular_threat_classification
                        if label_info and label_info.get('suggested_threat_label'):
                             threat_label = label_info.get('suggested_threat_label')
                    
                    return f"{score_str} {threat_label}".strip()

                except vt.error.APIError as e:
                    if "NotFoundError" in str(e): return "Not Found"
                    # Jika kena ban, beri jeda lebih lama sebelum coba lagi
                    if "NotAllowedError" in str(e):
                        print(f"🚨 Terkena ban sementara pada key {api_key[:4]}... Tidur 65 detik.")
                        time.sleep(65)
                        # Coba lagi attempt yang sama setelah tidur
                        continue
                    else:
                        raise e
                        
        except Exception as e:
            err_msg = str(e)
            if "QuotaExceededError" in err_msg:
                print(f"⚠️ VT Quota harian habis untuk key {api_key[:4]}... Coba kunci lain...")
                try:
                    # Ganti api_key dan coba lagi attempt yang sama
                    api_key = next(key_cycle)
                    api_request_times.setdefault(api_key, deque()) # Pastikan key baru ada di dict
                    continue
                except StopIteration:
                     return "Error: Quota semua key habis"
            
            if attempt < MAX_RETRIES - 1:
                sleep_time = 2 ** attempt + random.uniform(0.5, 1.5)
                print(f"⏳ Gagal, mencoba lagi dalam {sleep_time:.1f} detik...")
                time.sleep(sleep_time)
            else:
                return f"Error: {err_msg[:60]}"
    return "Error: Max retries exceeded"