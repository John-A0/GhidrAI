import os
import hashlib
import requests
import pefile

def run_initial_triage(file_path, vt_api_key):
    if not os.path.exists(file_path):
        return {
            "is_malware": True, 
            "confidence_score": 75, 
            "detected_features": "Local file missing.", 
            "conclusion": "Bypassed Static PE Check."
        }

    vt_result = "Not Checked"
    malicious_count = 0
    is_not_found = False

    if vt_api_key and len(vt_api_key) > 10:
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            url = f"https://www.virustotal.com/api/v3/files/{sha256_hash.hexdigest()}"
            response = requests.get(url, headers={"x-apikey": vt_api_key})
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                malicious_count = stats['malicious']
                vt_result = f"Found {malicious_count} detections."
            elif response.status_code == 404:
                vt_result = "Not Found (Potential Zero-Day)."
                is_not_found = True
        except Exception:
            vt_result = "VT API Error"

    suspicious_apis = {
        "Injection": ["VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "Ransomware": ["CryptEncrypt", "CryptDecrypt"],
        "Network": ["InternetOpen", "URLDownloadToFile", "WSAStartup", "socket"],
        "Evasion": ["IsDebuggerPresent", "GetTickCount", "LoadLibraryA", "GetProcAddress"]
    }
    
    found_details = []
    found_capabilities = set()
    is_packed = False
    max_entropy = 0.0

    try:
        pe = pefile.PE(file_path)
        with open(file_path, "rb") as f: content = f.read()
        
        for section in pe.sections:
            ent = section.get_entropy()
            if ent > max_entropy: max_entropy = ent
            if ent > 7.2:
                is_packed = True

        for category, apis in suspicious_apis.items():
            for api in apis:
                in_iat = False
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name and imp.name.decode('utf-8', errors='ignore') == api:
                                in_iat = True
                if in_iat or (api.encode('utf-8') in content):
                    found_details.append(api)
                    found_capabilities.add(category)
    except Exception:
        pass

    is_malicious = False
    confidence = 0
    conclusion = "Sample appears structurally safe."
    features_str = f"VT: {vt_result} | APIs Detected: {len(found_details)}"

    if malicious_count > 0:
        is_malicious = True
        confidence = min(100, 50 + (malicious_count * 5))
        conclusion = f"Flagged by {malicious_count} engines on VirusTotal."
    elif len(found_capabilities) > 0:
        is_malicious = True
        confidence = 85
        conclusion = f"Suspicious static capabilities found: {', '.join(found_capabilities)}."
    elif is_not_found and is_packed:
        is_malicious = True
        confidence = 90
        conclusion = f"ZERO-DAY ALERT: File is unknown to VT and highly obfuscated/packed (Entropy: {max_entropy:.2f})."
        features_str += f" | Packing Detected (Entropy: {max_entropy:.2f})"

    return {
        "is_malware": is_malicious,
        "confidence_score": confidence,
        "detected_features": features_str,
        "conclusion": conclusion
    }