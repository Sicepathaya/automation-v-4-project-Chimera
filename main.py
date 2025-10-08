# file: main.py

import concurrent.futures
import time
import asyncio
import sys

# Solusi untuk OSError: [WinError 6] The handle is invalid di Windows
if sys.platform == "win32" and sys.version_info >= (3, 8):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import concurrent.futures
import time
# Impor semua fungsi checker dari package 'checkers'
from checkers.virustotal import check_virustotal
from checkers.ctx import check_ctx
from checkers.otx import check_otx
from checkers.ibm_xforce import check_ibm_xforce
# from checkers.cyfirma import check_cyfirma

def run_all_checks(hash_value):
    """Menjalankan semua checker secara paralel untuk satu hash."""
    
    results = {}
    
    checkers_to_run = {
        "VirusTotal": check_virustotal,
        "CTX": check_ctx,
        "OTX AlienVault": check_otx,
        "IBM X-Force": check_ibm_xforce,
        # "Cyfirma": check_cyfirma,
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(checkers_to_run)) as executor:
        future_to_checker = {executor.submit(func, hash_value): name for name, func in checkers_to_run.items()}
        
        print("\n⏳ Menganalisis hash di semua platform...")
        
        for future in concurrent.futures.as_completed(future_to_checker):
            checker_name = future_to_checker[future]
            try:
                result = future.result()
                results[checker_name] = result
                print(f"  ✅ Hasil dari {checker_name} diterima.")
            except Exception as exc:
                results[checker_name] = f"Error: {exc}"
                print(f"  ❌ Terjadi error pada {checker_name}.")
    
    return results

def display_results(hash_value, results, file_name=""):
    """Menampilkan hasil dalam format kustom tanpa titik dua."""
    
    print("\n" + "="*80)
    print(f"[*] HASH {hash_value}")
    if file_name:
        print(f"[*] File {file_name}")
    print("="*80)
    
    sorted_platforms = ["VirusTotal", "IBM X-Force", "OTX AlienVault", "CTX"]

    for platform in sorted_platforms:
        result = results.get(platform)
        
        # Default output jika terjadi error atau data tidak ada
        output_str = f"{platform} {result}"

        # --- LOGIKA FORMATTING BARU TANPA TITIK DUA ---
        if isinstance(result, dict):
            if platform == "CTX":
                # Mengubah format CTX.io sesuai permintaan
                output_str = f"* CTX {result['status']} {result['detect']}"

        elif isinstance(result, str):
            if platform == "VirusTotal":
                # Menggunakan singkatan VT dan tanpa titik dua
                output_str = f"* Virus Total {result}"
            
            elif platform == "IBM X-Force":
                output_str = f"* IBM X Change {result}"
            
            elif platform == "OTX AlienVault":
                # Menggunakan singkatan OTX dan tanpa titik dua
                pulses_text = "none" if "0 pulses" in result or "Not Found" in result else result
                output_str = f"* OTX {pulses_text}"

        print(output_str)
        
    print("="*80)


if __name__ == "__main__":
    try:
        hash_input = input("➡️  Masukkan hash file: ").strip().lower()
        file_name_input = input("➡️  Masukkan nama file (opsional): ").strip()
        
        if not hash_input:
            print("❌ Input hash tidak boleh kosong.")
        else:
            start_time = time.time()
            final_results = run_all_checks(hash_input)
            display_results(hash_input, final_results, file_name_input)
            end_time = time.time()
            print(f"\n✨ Analisis selesai dalam {end_time - start_time:.2f} detik.")
    except KeyboardInterrupt:
        print("\nProses dibatalkan oleh pengguna.")