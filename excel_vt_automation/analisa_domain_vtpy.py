import vt
import pandas as pd
import time
import os
import json
import random
from itertools import cycle
from urllib.parse import urlparse
from tqdm import tqdm

# ==============================================================================
# ✅ CONFIGURATION
# ==============================================================================

API_KEYS = [
    "2e69c2efcc20299c0af7c4220a9e18a82c1aa86e3516f49fab73a17465cd64f0",
    "18bbc04d4ec0df2e043722761a9300ae27764a60f61db55a94f8d2808ef0677d"
]

INPUT_FILE = "input.xlsx"
OUTPUT_FILE = "gmail_domains_with_scores.xlsx"
DOMAIN_COLUMN = "Domain"
CACHE_FILE = "vt_cache.json"
MAX_RETRIES = 3

# VirusTotal free API allows 4 requests per minute per key
MAX_REQUESTS_PER_MINUTE_PER_KEY = 4
TOTAL_KEYS = len(API_KEYS)
MAX_REQUESTS_PER_MINUTE = MAX_REQUESTS_PER_MINUTE_PER_KEY * TOTAL_KEYS

# Hitung delay antar request (lebih longgar dari limit)
SAFE_REQUESTS_PER_MIN = MAX_REQUESTS_PER_MINUTE // 2  # pake 50% quota biar aman
DELAY_BETWEEN_REQUESTS = 60 / SAFE_REQUESTS_PER_MIN

# ==============================================================================
# 🧠 STATE
# ==============================================================================

cache_skor = {}
key_cycle = cycle(API_KEYS)  # round-robin API key


# ==============================================================================
# 🔧 FUNCTIONS
# ==============================================================================

def extract_domain(value):
    if pd.isna(value):
        return None
    value = str(value).strip()
    if '@' in value:
        return value.split('@')[-1]
    try:
        parsed = urlparse(value if '://' in value else 'http://' + value)
        return parsed.netloc or parsed.path
    except:
        return None


def load_cache():
    global cache_skor
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            try:
                cache_skor = json.load(f)
            except Exception:
                cache_skor = {}


def save_cache():
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache_skor, f)


def get_vt_score(domain, api_key):
    """Query VirusTotal untuk 1 domain"""
    for attempt in range(MAX_RETRIES):
        try:
            with vt.Client(api_key) as client:
                obj = client.get_object(f"/domains/{domain}")
                stats = obj.last_analysis_stats
                malicious = stats['malicious']
                total = sum(stats.values())
                return f"={malicious}/{total}"
        except Exception as e:
            err_msg = str(e)

            # Ban / Not Allowed
            if "NotAllowedError" in err_msg or "banned" in err_msg.lower():
                tqdm.write(f"🚨 API {api_key[:4]}... terkena BAN sementara!")
                return f"Error: Banned"

            # Kuota habis
            if "QuotaExceededError" in err_msg:
                tqdm.write(f"⚠️ API {api_key[:4]}... quota exceeded, tidur dulu...")
                time.sleep(60)  # cooldown
                continue

            if attempt < MAX_RETRIES - 1:
                sleep_time = 2 ** attempt + random.uniform(0.5, 2.0)
                tqdm.write(f"⏳ Retry dalam {sleep_time:.1f} detik...")
                time.sleep(sleep_time)
            else:
                return f"Error: {err_msg}"


# ==============================================================================
# 🧩 MAIN
# ==============================================================================

if not os.path.exists(INPUT_FILE):
    print(f"File input '{INPUT_FILE}' tidak ditemukan.")
    exit()

load_cache()
df = pd.read_excel(INPUT_FILE)

if 'VT_Score' not in df.columns:
    df['VT_Score'] = ""
else:
    df['VT_Score'] = df['VT_Score'].astype(str)

df['__domain'] = df[DOMAIN_COLUMN].apply(extract_domain)
df['__index'] = df.index

df_need_scan = df[df['__domain'].notna()][['__index', '__domain']]

# Loop semua domain
for _, row in tqdm(df_need_scan.iterrows(), total=len(df_need_scan), desc="Scanning"):
    idx = row['__index']
    domain = row['__domain']

    if domain in cache_skor:
        skor = cache_skor[domain]
    else:
        api_key = next(key_cycle)  # ambil key bergantian
        skor = get_vt_score(domain, api_key)
        cache_skor[domain] = skor
        save_cache()

        # Tunggu sebelum request berikutnya
        time.sleep(DELAY_BETWEEN_REQUESTS + random.uniform(0.2, 0.8))

    df.at[idx, 'VT_Score'] = skor

df.drop(columns=["__domain", "__index"], inplace=True)
df.to_excel(OUTPUT_FILE, index=False, engine="openpyxl")
print(f"✅ Selesai. Hasil disimpan di '{OUTPUT_FILE}'.")
