import pefile
import json
import sys
import os
import re

def extract_strings(target_file):
    """
    Extracts ASCII strings from the binary to catch obfuscated API calls.
    Uses 'ignore' error handling to avoid crashes on non-UTF-8 bytes.
    """
    with open(target_file, "rb") as f:
        data = f.read()
    # Find sequences of printable characters (length 4 or more)
    raw_strings = re.findall(b"[\x20-\x7E]{4,}", data)
    return [s.decode('utf-8', errors='ignore').lower() for s in raw_strings]

def mitre_mapper(target_file, mitre_json_path):
    if not os.path.exists(target_file):
        print(f"Error: File {target_file} not found.")
        return

    # 1. Load MITRE Data
    try:
        with open(mitre_json_path, "r") as f:
            mitre_windows_data = json.load(f)
    except Exception as e:
        print(f"Error loading JSON: {e}")
        return

    # 2. Extract APIs from Import Table (IAT) and Strings
    detected_apis = set()
    
    # PE Header Parsing
    try:
        pe = pefile.PE(target_file)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        detected_apis.add(imp.name.decode('utf-8', errors='ignore').lower())
    except Exception as e:
        print(f"Warning: Could not parse PE headers ({e})")

    # String Extraction (Catching Dynamic/Obfuscated calls)
    binary_strings = extract_strings(target_file)
    for s in binary_strings:
        detected_apis.add(s)

    # 3. MITRE Mapping Logic
    print(f"\n[*] Mapping {os.path.basename(target_file)} to MITRE ATT&CK...")
    print("-" * 80)
    
    total_techniques = 0
    
    for tactic, techniques in mitre_windows_data.items():
        found_in_tactic = False
        
        for technique_name, payload in techniques.items():
            # FIX: Ensure payload is a dictionary before calling .get()
            if not isinstance(payload, dict):
                continue
                
            matched_apis = []
            api_list = payload.get("api_list", [])
            
            # Check the api_list in the JSON against our detected set
            for api in api_list:
                if api.lower() in detected_apis:
                    matched_apis.append(api)

            if matched_apis:
                if not found_in_tactic:
                    print(f"\n[TACTIC] {tactic}")
                    found_in_tactic = True
                
                total_techniques += 1
                api_string = ", ".join(matched_apis[:5])
                if len(matched_apis) > 5:
                    api_string += "..."
                
                technique_id = payload.get("id", "N/A")
                print(f"  -> Technique: {technique_name} [{technique_id}]")
                print(f"     Matches:   {api_string}")

    if total_techniques == 0:
        print("[!] No MITRE techniques detected based on API imports.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 mitre_extract.py <target_exe> <mitre_for_windows.json>")
    else:
        mitre_mapper(sys.argv[1], sys.argv[2])