import os
import sys
import argparse
import numpy as np
import lightgbm as lgb
import thrember
import pickle
import json
import time
import re as _re
import hashlib
import requests
import zipfile
from pathlib import Path
def get_vt_threat_label(sha256: str) -> str:
    """Quick VT lookup — returns threat label string or empty string."""
    try:
        key_file = Path.home() / "sc0pe_Base" / "sc0pe_VT_apikey.txt"
        if not key_file.exists():
            return ""
        api_key = key_file.read_text(encoding="utf-8").splitlines()[0].strip()
        if not api_key:
            return ""
        
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if not resp.ok:
            return ""
        
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        threat_class = attrs.get("popular_threat_classification", {})
        return str(threat_class.get("suggested_threat_label") or "").strip()
    except Exception:
        return ""

# ============================================================
# 1️⃣ CONFIGURATION & DYNAMIC MAPPING
# ============================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(SCRIPT_DIR, "ml_analysis", "models")

# Mapping your actual filenames from the screenshot
MODEL_MAP = {
    "PE": "EMBER2024_PE.model",
    "Win32": "EMBER2024_Win32.model",
    "Win64": "EMBER2024_Win64.model",
    "DotNet": "EMBER2024_Dot_Net.model",
    "ELF": "EMBER2024_ELF.model",
    "APK": "EMBER2024_APK.model",
    "PDF": "EMBER2024_PDF.model",
    "PACKER": "EMBER2024_packer.model",
    "FAMILY": "EMBER2024_family.model",
    "BEHAVIOR": "EMBER2024_behavior.model",
    "EXPLOIT": "EMBER2024_exploit.model"
}
import hashlib

def get_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
# ============================================================
# 2️⃣ SAFE LOADING WRAPPER (The "Anti-Crash" Fix)
# ============================================================
def safe_predict(model_key, data_vector, h_notes):
    """
    Run one ML model safely.

    Reliability rule:
      - A genuine model prediction of 0.0 stays 0.0.
      - Missing models, load failures, empty ensembles, or prediction errors
        return None so failure is not misreported as zero risk.
    """
    model_name = MODEL_MAP.get(model_key)
    if not model_name:
        h_notes.append(f"[ML] No model mapping is configured for: {model_key}")
        return None

    path = os.path.join(MODEL_DIR, model_name)
    if not os.path.exists(path):
        h_notes.append(f"[ML] Model file is unavailable: {model_name}")
        return None

    try:
        with open(path, "rb") as f:
            header = f.read(4)
            f.seek(0)

            if header.startswith(b"\x80"):
                obj = pickle.load(f)

                if isinstance(obj, list):
                    scores = []
                    for item in obj:
                        if not hasattr(item, "predict"):
                            continue
                        res = np.asarray(item.predict(data_vector)).reshape(-1)
                        if res.size:
                            scores.append(float(res[0]))

                    if not scores:
                        h_notes.append(
                            f"[ML] Model ensemble produced no usable predictions: {model_name}"
                        )
                        return None

                    return float(sum(scores) / len(scores))

                model = obj
            else:
                model = lgb.Booster(model_file=path)

        if not hasattr(model, "predict"):
            h_notes.append(f"[ML] Loaded object has no predict() method: {model_name}")
            return None

        prediction = np.asarray(model.predict(data_vector))
        if prediction.size == 0:
            h_notes.append(f"[ML] Model returned an empty prediction: {model_name}")
            return None

        first = prediction[0]
        if isinstance(first, np.ndarray):
            return first

        return float(first)

    except Exception as exc:
        h_notes.append(
            f"[ML] Prediction unavailable for {model_name}: "
            f"{type(exc).__name__}: {exc}"
        )
        return None

# ============================================================
# 3️⃣ ENHANCED FILE INSPECTION
# ============================================================
def get_detailed_type(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read(4096)
            if data.startswith(b"MZ"):
                if b"BSJB" in data: return "DotNet"
                pe_off = int.from_bytes(data[0x3C:0x40], "little")
                machine = data[pe_off+4:pe_off+6]
                if machine == b"\x4c\x01": return "Win32"
                if machine == b"\x64\x86": return "Win64"
                return "PE"
            if data.startswith(b"\x7fELF"):
                return "ELF"

            if data.startswith(b"%PDF"):
                return "PDF"

            # APK files are ZIP containers, but a generic ZIP must not be
            # classified as APK just because both start with the PK signature.
            if data[:2] == b"PK":
                try:
                    if not zipfile.is_zipfile(filepath):
                        return "UNKNOWN"

                    with zipfile.ZipFile(filepath, "r") as archive:
                        names = {
                            str(name).replace("\\", "/").lstrip("/")
                            for name in archive.namelist()
                        }

                    has_manifest = "AndroidManifest.xml" in names
                    has_dex = any(
                        _re.fullmatch(r"classes\d*\.dex", Path(name).name)
                        for name in names
                    )
                    has_apk_resources = "resources.arsc" in names

                    if has_manifest and (has_dex or has_apk_resources):
                        return "APK"

                    return "UNKNOWN"
                except (OSError, zipfile.BadZipFile, RuntimeError):
                    return "UNKNOWN"

    except Exception:
        pass

    return "UNKNOWN"
import subprocess

def get_signature_info(filepath):
    """Verifies signature and returns (is_valid, signer_name)."""
    try:
        # Requesting Status and Signer Subject from PowerShell
        cmd = f'Get-AuthenticodeSignature "{filepath}" | Select-Object Status, @{{Name="Signer";Expression={{$_.SignerCertificate.Subject}}}} | ConvertTo-Json'
        output = subprocess.check_output(['powershell', '-Command', cmd], shell=True).decode().strip()
        
        import json
        data = json.loads(output)
        
        # Status 0 is 'Valid'
        is_valid = data.get("Status") == 0
        signer = data.get("Signer", "")
        
        return is_valid, signer
    except:
        return False, ""

def run_heuristics(filepath, ml_score):
    risk_adj = 0
    notes = []
    clean_path = filepath.lower()
    base_name = os.path.basename(clean_path)

    # System & Troubleshooting (Sysinternals & standard tools)
    ADMIN_TOOLS = [
        "sysmon.exe", "sysmon64.exe", "procmon.exe", "procexp.exe", 
        "autoruns.exe", "tcpview.exe", "procdump.exe", "accesschk.exe",
        "handle.exe", "vmmap.exe", "rammap.exe", "whois.exe"
    ]

    # Security & Network Analysis
    NET_TOOLS = [
        "wireshark.exe", "tshark.exe", "nmap.exe", "winpcap.exe", 
        "npcap.exe", "putty.exe", "winscp.exe", "filezilla.exe",
        "zenmap.exe", "advanced_ip_scanner.exe"
    ]

    # Developer & Compilation Tools (AI often flags these as "droppers")
    DEV_TOOLS = [
        "git.exe", "python.exe", "node.exe", "code.exe", "powershell_ise.exe",
        "gcc.exe", "make.exe", "docker.exe", "kubectl.exe", "vstest.console.exe",
        "msbuild.exe", "devenv.exe", "javac.exe"
    ]

    # Benchmarking & Hardware (Often use low-level drivers that look like rootkits)
    HW_TOOLS = [
        "cpuz.exe", "gpuz.exe", "hwinfo64.exe", "coretemp.exe", 
        "perfmon.exe", "resmon.exe"
    ]
    
    GOLDEN_TOOLS = ADMIN_TOOLS + NET_TOOLS + DEV_TOOLS + HW_TOOLS

    # 2. EXTENDED TRUSTED ZONES
    TRUSTED_ZONES = [
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\program files",
        "c:\\program files (x86)",
        "c:\\windows\\winsxs",
        "c:\\windows\\microsoft.net", # For .NET framework binaries
        "c:\\programdata"            # Common for shared app resources
    ]
    TRUSTED_PUBLISHERS = [
        "Microsoft", "Google", "Mozilla", "Intel", "Cisco", 
        "Apple", "NVIDIA", "Advanced Micro Devices", "Oracle"
    ]

    # 2. Get detailed signature info
    is_signed, signer_name = get_signature_info(filepath)

    # 3. Check for "Golden Tool" Trust
    is_golden_match = any(tool.lower() in base_name.lower() for tool in GOLDEN_TOOLS)
    if is_golden_match and is_signed:
        risk_adj -= 95 
        notes.append(f"[-] Identified Known Admin Tool: {base_name} (Global Trust Applied)")
        return risk_adj, notes, False

    # 4. NEW: Check for Publisher Trust
    # This catches legitimate software not in your specific tool lists
    if is_signed and any(pub.lower() in signer_name.lower() for pub in TRUSTED_PUBLISHERS):
        risk_adj -= 85
        notes.append(f"[-] Verified Publisher: {signer_name}")
        return risk_adj, notes, False

    # 5. Existing System Zone Logic
    
    in_system_zone = any(zone in clean_path for zone in TRUSTED_ZONES)

    if in_system_zone:
        if is_signed:
            risk_adj -= 80 
            notes.append(f"[-] Verified {signer_name} Signature in System Path")
        else:
            risk_adj += 25 # Increased penalty for unsigned in system folders
            notes.append("[!] CRITICAL: Unsigned binary in System Folder!")

    # 4. EICAR String Search
    try:
        with open(filepath, "r", errors="ignore") as f:
            if "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" in f.read():
                risk_adj += 100
                notes.append("[!!!] EICAR SIGNATURE DETECTED")
    except: pass

    return risk_adj, notes, in_system_zone
# ============================================================
# 4️⃣ ANALYSIS ENGINE
# ============================================================
def analyze_binary(sample_path, json_out=False):
    sample_path = os.path.abspath(sample_path) 
    f_type = get_detailed_type(sample_path)
    base_name = os.path.basename(sample_path)
    file_hash = get_sha256(sample_path)
    h_notes = []

    # 1. Feature Extraction
    try:
        extractor = thrember.PEFeatureExtractor()
        with open(sample_path, "rb") as f:
            byte_array = np.frombuffer(f.read(), dtype=np.uint8)
        X = np.expand_dims(extractor.feature_vector(byte_array), axis=0)
    except Exception as e:
        print(f"[-] Extraction Error: {e}")
        return

    # 2. Multi-Model Pipeline
    # A genuine 0.0 is a valid prediction and must not trigger fallback.
    ml_conf = safe_predict(f_type, X, h_notes)
    primary_model_key = f_type
    ml_fallback_used = False

    if ml_conf is None and f_type not in {"UNKNOWN", "PE"}:
        h_notes.append(
            f"[ML] {f_type} model unavailable; attempting generic PE fallback."
        )
        ml_conf = safe_predict("PE", X, h_notes)
        if ml_conf is not None:
            primary_model_key = "PE"
            ml_fallback_used = True

    ml_scan_error = ""
    if ml_conf is None:
        ml_scan_error = (
            f"Primary ML prediction is unavailable for target type {f_type}; "
            "no malware-probability score was produced."
        )
        h_notes.append(f"[ML] {ml_scan_error}")

    packer_score = safe_predict("PACKER", X, h_notes)
    behavior_score = safe_predict("BEHAVIOR", X, h_notes)

    family_info = "N/A"
    if ml_conf is not None and ml_conf > 0.6:
        fam_results = safe_predict("FAMILY", X, h_notes)
        if isinstance(fam_results, (list, np.ndarray)):
            family_info = f"Cluster_{np.argmax(fam_results)}"

    # ============================================================
    # 3️⃣ SOC WEIGHTED SCORE FUSION (Nuanced Version)
    # ============================================================
    base_score = (ml_conf * 100) if ml_conf is not None else None

    multiplier = 1.0
    if behavior_score is not None and behavior_score > 0.5:
        multiplier += 0.25
    if packer_score is not None and packer_score > 0.7:
        multiplier += 0.35

    weighted_risk = (base_score * multiplier) if base_score is not None else None

    h_adj, h_findings, in_system_zone = run_heuristics(
        sample_path,
        ml_conf if ml_conf is not None else 0.0,
    )
    h_notes.extend(h_findings)

    is_signed = "Verified Microsoft Signature" in str(h_findings)
    is_golden = "Global Trust" in str(h_findings)
    is_critical = "[!] CRITICAL" in str(h_findings)

    final_risk = None

    if weighted_risk is not None:
        if is_signed and is_golden:
            final_risk = weighted_risk * 0.02
        elif is_signed and in_system_zone:
            final_risk = min(weighted_risk * 0.10, 15.0)
        elif is_critical:
            ml_impact = weighted_risk * 0.6
            location_penalty = 25.0
            final_risk = ml_impact + location_penalty
            if packer_score is not None and packer_score > 0.8:
                final_risk += 15
        else:
            final_risk = weighted_risk + h_adj

        final_risk = max(0, min(100, final_risk))

    # ── VT threat label enrichment ──
    vt_label = get_vt_threat_label(file_hash)

    clean_name = _re.sub(r'^[0-9a-f]{8,10}_', '', base_name, flags=_re.IGNORECASE)

    report_data = {
        "filename": clean_name,
        "target_type": f_type,
        "sha256": file_hash,
        "family": family_info,
        "notes": h_notes,
        "vt_threat_label": vt_label,
        "ml_primary_model": primary_model_key,
        "ml_fallback_used": ml_fallback_used,
    }

    if ml_conf is not None:
        report_data["ml_conf"] = float(ml_conf)
    if behavior_score is not None:
        report_data["behavior_score"] = float(behavior_score)
    if packer_score is not None:
        report_data["packer_score"] = float(packer_score)
    if final_risk is not None:
        report_data["final_risk"] = float(final_risk)
    if ml_scan_error:
        report_data["ml_scan_error"] = ml_scan_error

    if not json_out:
        if final_risk is None:
            status, color = "ML UNAVAILABLE", "\033[93m"
        elif final_risk > 75:
            status, color = "MALICIOUS", "\033[91m"
        elif final_risk > 45:
            status, color = "SUSPICIOUS", "\033[93m"
        elif final_risk > 15:
            status, color = "LOW RISK", "\033[94m"
        else:
            status, color = "LOW CONTEXTUAL RISK", "\033[92m"

        ml_text = f"{ml_conf:.4f}" if ml_conf is not None else "N/A"
        behavior_text = f"{behavior_score:.4f}" if behavior_score is not None else "N/A"
        packer_text = f"{packer_score:.4f}" if packer_score is not None else "N/A"
        risk_text = f"{final_risk:.2f}/100" if final_risk is not None else "N/A"

        print("\n" + "═"*65)
        print(f"  MalTracer EMBER 2024 | STATIC ML ANALYSIS: {base_name}")
        print("═"*65)
        print(f" Target Type    : {f_type}")
        print(f" Detection Base : {ml_text}")
        print(f" Behavior Score : {behavior_text}")
        print(f" Packer/Obfusc. : {packer_text}")
        print(f" Family Group   : {family_info}")
        print(f" SHA-256        : {file_hash}")
        print(f" Final Risk     : {color}{risk_text} ({status})\033[0m")
        print("─"*65)
        if h_notes:
            for n in sorted(set(h_notes)):
                print(f" > {n}")
        print("═"*65 + "\n")

    if json_out:
        return report_data

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    
    # Catching the True/False passed from Malsecure.py
    parser.add_argument("report_mode", nargs='?', default="False") 
    
    args = parser.parse_args()
    
    # Logic to check if we are in JSON/Report mode
    use_json = args.json or (args.report_mode.lower() == "true")

    if os.path.exists(args.file):
        result = analyze_binary(args.file, json_out=use_json)
        
        if use_json:
            # 1. Generate timestamped filename to match other modules
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            report_name = f"sc0pe_behavior_report_{timestamp}.json"

            try:
                # 2. Save the report to a file for the UI
                with open(report_name, "w") as f:
                    json.dump(result, f, indent=4)
            except Exception as e:
                # Avoid printing errors to stdout if the UI is expecting clean JSON
                if not use_json:
                    print(f"[-] Failed to save report: {e}")

            # 3. Print the JSON to stdout so the UI can capture it in real-time
            if isinstance(result, dict) and result.get("ml_scan_error"):
                print(result["ml_scan_error"], file=sys.stderr)
                sys.exit(2)

            print(json.dumps(result))