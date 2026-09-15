#!/usr/bin/env python3

import concurrent.futures
import copy
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "webui_uploads"
REPORTS_ROOT = BASE_DIR 
REPORTS_MAIN_DIR = BASE_DIR
REPORTS_AI_DIR = REPORTS_ROOT / "ai"
REPORTS_VT_DIR = REPORTS_ROOT / "virustotal"
MAX_UPLOAD_MB = 48 
ANALYSIS_TIMEOUT_SECONDS = 900
MAX_JOB_HISTORY = 150
MAX_PANEL_ITEMS = 240
MAX_TABLE_ROWS = 240
MAX_TABLE_COLS = 14
PYTHON_BIN = sys.executable or "python3"
ENTRYPOINT = BASE_DIR / "Malsecure.py"


@dataclass(frozen=True)
class AnalysisPreset:
    label: str
    description: str
    args: Tuple[str, ...]
    report_default: bool = False


PRESETS: "OrderedDict[str, AnalysisPreset]" = OrderedDict(
    {
        "analyze": AnalysisPreset(
            label="Standard Analysis",
            description="OS/file type auto-detection with static triage, MITRE ATT&CK Map, and VirusTotal file lookup.",
            args=("--analyze",),
            report_default=True,
        ),
        "docs": AnalysisPreset(
            label="Document",
            description="Document, macro and VB-family script analysis with report and VirusTotal file lookup.",
            args=("--docs",),
            report_default=True,
        ),
        "archive": AnalysisPreset(
            label="Archive",
            description="Archive inspection with nested IOC/YARA triage, JSON report, optional AI support, and VirusTotal file lookup.",
            args=("--archive",),
            report_default=True,
        ),
        "packer": AnalysisPreset(
            label="Packer Detect",
            description="Packer signature detection for packed binaries with JSON report output.",
            args=("--packer",),
            report_default=True,
        ),
        "domain": AnalysisPreset(
            label="Domain/IOC",
            description="URL/IP/email extraction with JSON report support.",
            args=("--domain",),
            report_default=True,
        ),
        "lang": AnalysisPreset(
            label="Language",
            description="Programming language fingerprint analysis with JSON report output.",
            args=("--lang",),
            report_default=True,
        ),
        "vtFile": AnalysisPreset(
            label="VirusTotal File",
            description="Query file hash on VirusTotal (requires API key via --key_init).",
            args=("--vtFile",),
            report_default=True,
        ),
        "behavioral": AnalysisPreset(
            label="ML Behavioral Scan",
            description="EMBER ML model analysis with heuristic weighted risk scoring.",
            args=("--behavioral",), # This flag tells webapp.py to run your script
            report_default=True,
        )
    }
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SC0PE_WEB_SECRET", "change-me-in-production")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_MAIN_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_AI_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_VT_DIR.mkdir(parents=True, exist_ok=True)

JOB_QUEUE: "queue.Queue[str]" = queue.Queue()
JOBS: Dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
JOB_SEQUENCE = 0
WORKER_THREAD: Optional[threading.Thread] = None


def _ts_to_text(ts: Optional[float]) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _trim_text(text: str, max_len: int = 1600) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _to_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _normalize_inline_text(text: str) -> str:
    # Compact UI text for cards/tables: remove tabs/newlines and collapse whitespace.
    out = str(text or "")
    out = out.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    out = re.sub(r"\s{2,}", " ", out)
    return out.strip()


def _report_snapshot() -> Dict[Path, int]:
    snap: Dict[Path, int] = {}
    for candidate in REPORTS_ROOT.glob("sc0pe_*_report.json"):
        try:
            snap[candidate] = candidate.stat().st_mtime_ns
        except OSError:
            continue
    return snap


def _detect_new_reports(before: Dict[Path, int]) -> List[Path]:
    changed: List[Tuple[int, Path]] = []
    for candidate in REPORTS_ROOT.glob("sc0pe_*_report.json"):
        try:
            mtime_ns = candidate.stat().st_mtime_ns
        except OSError:
            continue
        if candidate not in before or mtime_ns > before[candidate]:
            changed.append((mtime_ns, candidate))
    changed.sort(key=lambda item: item[0], reverse=True)
    return [item[1] for item in changed]


def _select_report_paths(changed_reports: List[Path], ai_enabled: bool) -> Tuple[Optional[Path], Optional[Path]]:
    if not changed_reports:
        return None, None

    ai_candidates = [path for path in changed_reports if path.name == "sc0pe_ai_report.json"]
    non_ai_candidates = [path for path in changed_reports if path.name != "sc0pe_ai_report.json"]

    ai_report = ai_candidates[0] if ai_candidates else None
    if ai_enabled and non_ai_candidates:
        return non_ai_candidates[0], ai_report
    return changed_reports[0], ai_report


def _report_bucket_dir(bucket: str) -> Path:
    if bucket == "ai":
        return REPORTS_AI_DIR
    if bucket == "vt":
        return REPORTS_VT_DIR
    return REPORTS_MAIN_DIR


def _unique_report_destination(dst_dir: Path, filename: str) -> Path:
    safe_name = Path(str(filename)).name
    dst = dst_dir / safe_name
    if not dst.exists():
        return dst
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return dst_dir / f"{dst.stem}_{stamp}_{uuid.uuid4().hex[:6]}{dst.suffix}"


def _store_generated_report(src_report: Optional[Path], bucket: str) -> str:
    if src_report is None:
        return ""

    src = src_report if src_report.is_absolute() else (BASE_DIR / src_report)
    if not src.exists():
        return ""

    dst_dir = _report_bucket_dir(bucket)
    dst = _unique_report_destination(dst_dir, src.name)
    try:
        shutil.move(str(src), str(dst))
    except Exception:  # noqa: BLE001
        try:
            shutil.copy2(str(src), str(dst))
            src.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            return ""

    try:
        return str(dst.relative_to(BASE_DIR))
    except ValueError:
        return str(dst)


def _resolve_report_path(report_path: str) -> Optional[Path]:
    if not report_path:
        return None

    candidate = Path(report_path)
    if not candidate.is_absolute():
        candidate = BASE_DIR / candidate

    try:
        resolved = candidate.resolve()
        base = BASE_DIR.resolve()
    except OSError:
        return None

    # Keep report resolution limited to project directory.
    if resolved != base and base not in resolved.parents:
        return None
    return resolved


def _load_report_for_job(job: dict) -> dict:
    report_ui = {
        "summary": [],
        "hashes": [],
        "categories": [],
        "windows_api_categories": [],
        "mitre_rows": [],
        "vt_section": {
            "available": False,
            "summary": [],
            "threat_names": [],
            "threat_categories": [],
            "detections": [],
            "error": "",
        },
        "interesting_patterns": [],
        "matched_rules_rows": [],
        "sections": [],
        "metadata": [],
        "extra_panels": [],
        "detailed_panels": [],
        "ai_output": "",
        "ai_iocs": [],
        "ai_context": [],
    }

    out = {
        "report_loaded": False,
        "report_file_label": str(job.get("report_path") or ""),
        "report_load_error": "",
        "report_ui": report_ui,
        "ai_loaded": False,
        "ai_file_label": str(job.get("ai_report_path") or ""),
        "ai_load_error": "",
        "ai_ui": {
            "ai_output": "",
            "ai_iocs": [],
            "ai_context": [],
        },
    }

    resolved = _resolve_report_path(str(job.get("report_path") or ""))
    if not resolved:
        if job.get("report_expected"):
            out["report_load_error"] = "Report path is missing or invalid."
        return out

    out["report_file_label"] = str(resolved.name)
    if not resolved.exists():
        out["report_load_error"] = f"Report file not found: {resolved.name}"
        return out

    try:
        report_data = json.loads(resolved.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        out["report_load_error"] = f"Report parse error: {exc}"
        return out

    # Inject VT threat label for behavioral jobs without modifying the file
    if job.get("vt_threat_label"):
        report_data = dict(report_data)  # shallow copy, don't mutate the original
        report_data["vt_threat_label"] = job["vt_threat_label"]

    out["report_loaded"] = True
    out["report_ui"] = build_frontend_payload(report_data)

    ai_resolved = _resolve_report_path(str(job.get("ai_report_path") or ""))
    if ai_resolved:
        out["ai_file_label"] = str(ai_resolved.name)
        if ai_resolved.exists():
            try:
                ai_data = json.loads(ai_resolved.read_text(encoding="utf-8"))
                ai_payload = build_frontend_payload(ai_data)
                out["ai_loaded"] = True
                out["ai_ui"] = {
                    "ai_output": str(ai_payload.get("ai_output") or ""),
                    "ai_iocs": ai_payload.get("ai_iocs") or [],
                    "ai_context": ai_payload.get("ai_context") or [],
                }
            except Exception as exc:  # noqa: BLE001
                out["ai_load_error"] = f"AI report parse error: {exc}"
        else:
            out["ai_load_error"] = f"AI report file not found: {ai_resolved.name}"

    return out


def _fmt_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "-"
    text = _normalize_inline_text(str(value))
    if not text:
        return "-"
    if len(text) > 120:
        return text[:117] + "..."
    return text


def _labelize_key(key: str) -> str:
    normalized = str(key).strip().replace("_", " ")
    return " ".join(part.capitalize() for part in normalized.split())


def _ioc_kind_label(kind: str) -> str:
    normalized = str(kind or "").strip().lower().replace("_", " ").replace("-", " ")
    aliases = {
        "ips": "IP Addresses",
        "ip": "IP Addresses",
        "ip address": "IP Addresses",
        "ip addresses": "IP Addresses",
    }
    if normalized in aliases:
        return aliases[normalized]
    return _labelize_key(kind)


def _count_items(value: object) -> int:
    if isinstance(value, dict):
        total = 0
        for item in value.values():
            if isinstance(item, (list, tuple, set)):
                total += len(item)
            elif isinstance(item, dict):
                total += len(item)
            elif item:
                total += 1
        return total
    if isinstance(value, (list, tuple, set)):
        return len(value)
    if isinstance(value, int):
        return value
    return 0


def _is_scalar(value: object) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def _safe_panel_text(value: object) -> str:
    if _is_scalar(value):
        return _fmt_value(value)
    return _trim_text(_normalize_inline_text(json.dumps(value, ensure_ascii=False)), 420)


def build_summary(report_data: Optional[dict]) -> List[dict]:
    if not isinstance(report_data, dict):
        return []

    summary: List[dict] = []
    
    # --- ML / STATIC HEURISTIC SUMMARY ---
    # Keep the raw EMBER model score distinct from the final contextual risk.
    if "ml_conf" in report_data:
        ml_raw = int(round(float(report_data.get("ml_conf", 0)) * 100))
        summary.append({
            "label": "EMBER Raw Score",
            "value": f"{ml_raw}/100",
        })

    if "target_type" in report_data:
        summary.append({"label": "Target Type", "value": str(report_data["target_type"])})

    if "behavior_score" in report_data:
        behavior_value = float(report_data.get("behavior_score", 0)) * 100
        summary.append({
            "label": "Static Behavior Heuristic",
            "value": f"{behavior_value:.1f}/100",
        })

    if "packer_score" in report_data:
        packer_value = float(report_data.get("packer_score", 0)) * 100
        summary.append({
            "label": "Packer / Obfuscation Heuristic",
            "value": f"{packer_value:.1f}/100",
        })

    if "final_risk" in report_data:
        risk_val = float(report_data.get("final_risk", 0))
        sev = "high" if risk_val >= 70 else ("medium" if risk_val >= 20 else "low")
        summary.append({
            "label": "Final Contextual Risk",
            "value": f"{risk_val:.2f}/100",
            "severity": sev,
        })

    # Added SHA-256 to match terminal
    if "hash_sha256" in report_data or "sha256" in report_data:
        val = report_data.get("hash_sha256") or report_data.get("sha256")
        summary.append({"label": "SHA-256", "value": str(val)})
  
    # Keep VirusTotal's readable threat label separate from the ML family-cluster
    # index. This avoids presenting an unmapped Cluster_N value as a named
    # malware family.
    vt_data = report_data.get("virustotal_file") or {}

    # Behavioral reports can carry the VirusTotal label flat, while standard
    # reports store the VirusTotal payload under "virustotal_file".
    vt_label = (
        str(report_data.get("vt_threat_label") or "").strip()
        or str(vt_data.get("threat_label") or "").strip()
    )

    cluster_family = str(report_data.get("family") or "").strip()
    has_ml_cluster = bool(
        cluster_family
        and cluster_family.lower() not in {"n/a", "na", "none", "-", "unknown"}
        and cluster_family.lower().startswith("cluster_")
    )

    summary.append(
        {
            "label": "Malware Name",
            "value": _fmt_value(vt_label) if vt_label else "N/A",
        }
    )

    if has_ml_cluster:
        summary.append(
            {
                "label": "ML Family Cluster",
                "value": _fmt_value(cluster_family),
            }
        )
    summary.append(
        {
            "label": "Filename",
            "value": _fmt_value(report_data.get("filename") or report_data.get("target_file")),
        }
    )

    for key, label in (("hash_md5", "MD5"), ("hash_sha1", "SHA1"), ("hash_sha256", "SHA256")):
        if report_data.get(key):
            summary.append({"label": label, "value": _fmt_value(report_data.get(key))})

    if "categorized_findings" in report_data:
        try:
            categorized_findings = max(0, int(report_data.get("categorized_findings") or 0))
        except Exception:
            categorized_findings = 0
        summary.append({"label": "Categorized Hits", "value": str(categorized_findings)})

    count_map = (
        ("categories", "Categorized Hits"),
        ("matched_rules", "Matched YARA"),
        ("interesting_string_patterns", "Interesting Patterns"),
        ("detected_languages", "Detected Languages"),
        ("linked_dll", "Linked DLLs"),
        ("libraries", "Libraries"),
        ("attachments", "Attachments"),
        ("embedded_files", "Embedded Files"),
        ("extracted_urls", "Extracted URLs"),
    )
    for key, label in count_map:
        if key in report_data:
            if label == "Categorized Hits" and any(str(item.get("label")) == "Categorized Hits" for item in summary):
                continue
            summary.append({"label": label, "value": str(_count_items(report_data.get(key)))})

    # Some analyzers (e.g., Android/JAR source analysis) keep category counts under
    # source_summary.category_counts instead of top-level "categories".
    has_categorized_hits = any(str(item.get("label")) == "Categorized Hits" for item in summary)
    if not has_categorized_hits:
        derived_categories = _extract_categories(report_data)
        if derived_categories:
            total_hits = sum(int(row.get("count") or 0) for row in derived_categories)
            summary.append({"label": "Categorized Hits", "value": str(total_hits)})

    mitre_rows = _extract_mitre_rows(report_data)
    if mitre_rows:
        summary.append({"label": "MITRE Tactics", "value": str(len(mitre_rows))})
        summary.append(
            {
                "label": "MITRE Associations",
                "value": str(int(report_data.get("mitre_technique_count") or sum(int(t.get("technique_count") or 0) for t in mitre_rows))),
            }
        )
        summary.append(
            {
                "label": "MITRE API Matches",
                "value": str(int(report_data.get("mitre_api_match_count") or sum(int(t.get("score") or 0) for t in mitre_rows))),
            }
        )

    

    perm_section = _extract_permissions_section(report_data)
    perm_counts = perm_section.get("counts", {}) if isinstance(perm_section, dict) else {}
    dangerous_count = int(perm_counts.get("dangerous") or 0)
    special_count = int(perm_counts.get("special") or 0)
    if dangerous_count > 0:
        summary.append({"label": "Dangerous Perms", "value": str(dangerous_count)})
    if special_count > 0:
        summary.append({"label": "Special Perms", "value": str(special_count)})

    return summary[:12]


def _render_inline(value: object, max_items: int = 6, depth: int = 0) -> str:
    if _is_scalar(value):
        return _fmt_value(value)

    if depth >= 2:
        nested_count = _count_items(value)
        if nested_count > 0:
            return f"{nested_count} item"
        if isinstance(value, dict):
            return f"{len(value)} key"
        if isinstance(value, list):
            return f"{len(value)} item"
        return "-"

    if isinstance(value, list):
        parts = [_render_inline(item, max_items=3, depth=depth + 1) for item in value[:max_items]]
        parts = [part for part in parts if part and part != "-"]
        suffix = ""
        if len(value) > max_items:
            suffix = f" (+{len(value) - max_items} more)"
        return _trim_text(_normalize_inline_text(", ".join(parts) + suffix), 220)

    if isinstance(value, dict):
        pairs: List[str] = []
        items = list(value.items())
        for key, item in items[:max_items]:
            rendered = _render_inline(item, max_items=3, depth=depth + 1)
            if rendered and rendered != "-":
                pairs.append(f"{_labelize_key(str(key))}: {rendered}")
        suffix = ""
        if len(items) > max_items:
            suffix = f" (+{len(items) - max_items} more)"
        return _trim_text(_normalize_inline_text("; ".join(pairs) + suffix), 220)

    return _fmt_value(value)


def _serialize_entry(value: object) -> str:
    return _render_inline(value)


def _has_meaningful_golang_data(value: object) -> bool:
    if not isinstance(value, dict):
        return bool(value)

    if bool(value.get("detected")):
        return True
    if bool(value.get("analysis_performed")):
        return True
    try:
        if int(value.get("total_findings") or 0) > 0:
            return True
    except (TypeError, ValueError):
        pass
    if isinstance(value.get("go_sections"), list) and len(value.get("go_sections") or []) > 0:
        return True
    if isinstance(value.get("findings_by_category"), dict) and _count_items(value.get("findings_by_category")) > 0:
        return True
    if isinstance(value.get("finding_counts"), dict) and _count_items(value.get("finding_counts")) > 0:
        return True
    if str(value.get("error") or "").strip():
        return True
    return False


def _preview_items(value: object, limit: int = 18) -> List[str]:
    if isinstance(value, list):
        return [_serialize_entry(item) for item in value[:limit]]

    if isinstance(value, dict):
        preview: List[str] = []
        for key, item in list(value.items())[:limit]:
            if isinstance(item, (list, tuple, set, dict)):
                preview.append(f"{key}: {_count_items(item)} item")
            else:
                preview.append(f"{key}: {_fmt_value(item)}")
        return preview

    if value is None:
        return []

    return [_fmt_value(value)]


def _extract_categories(report_data: dict) -> List[dict]:
    merged: Dict[str, int] = {}

    def _merge_counts(cat_obj: object) -> None:
        if not isinstance(cat_obj, dict):
            return
        for key, value in cat_obj.items():
            count = _count_items(value)
            if count <= 0:
                continue
            name = str(key).strip()
            if not name:
                continue
            merged[name] = merged.get(name, 0) + int(count)

    # Generic analyzer format (Windows/Linux/etc.).
    _merge_counts(report_data.get("categories"))

    # Android/JAR source scanner format.
    source_summary = report_data.get("source_summary")
    if isinstance(source_summary, dict):
        _merge_counts(source_summary.get("category_counts"))

    # Last-resort derivation from source findings when summary counts are absent.
    if not merged:
        findings = report_data.get("source_findings")
        if isinstance(findings, list):
            for item in findings:
                if not isinstance(item, dict):
                    continue
                cats = item.get("categories")
                if not isinstance(cats, list):
                    continue
                for cat in cats:
                    cname = str(cat).strip()
                    if not cname:
                        continue
                    merged[cname] = merged.get(cname, 0) + 1

    rows = [{"name": name, "count": count} for name, count in merged.items() if count > 0]
    rows.sort(key=lambda row: row["count"], reverse=True)
    return rows


def _extract_interesting_patterns(report_data: dict) -> List[str]:
    raw = report_data.get("interesting_string_patterns")
    if not isinstance(raw, list):
        return []

    values: List[str] = []
    seen = set()
    for item in raw:
        candidate = ""
        if isinstance(item, dict):
            # Explicitly ignore "suspicious" marker in UI output.
            candidate = _normalize_inline_text(str(item.get("value") or ""))
        elif item is not None:
            candidate = _normalize_inline_text(str(item))

        if not candidate:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        values.append(candidate)
    return values[:200]


def _extract_source_pattern_rows(report_data: dict) -> List[dict]:
    raw = report_data.get("source_findings")
    if not isinstance(raw, list):
        return []

    rows: List[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue

        file_name = _normalize_inline_text(str(item.get("file_name") or item.get("file") or ""))
        categories_raw = item.get("categories")
        patterns_raw = item.get("patterns")

        categories: List[str] = []
        if isinstance(categories_raw, list):
            seen_cat = set()
            for cat in categories_raw:
                cname = _normalize_inline_text(str(cat or ""))
                if not cname:
                    continue
                key = cname.lower()
                if key in seen_cat:
                    continue
                seen_cat.add(key)
                categories.append(cname)

        patterns: List[str] = []
        if isinstance(patterns_raw, list):
            seen_pat = set()
            for pat in patterns_raw:
                pname = _normalize_inline_text(str(pat or ""))
                if not pname:
                    continue
                key = pname.lower()
                if key in seen_pat:
                    continue
                seen_pat.add(key)
                patterns.append(pname)

        if not file_name and not patterns:
            continue

        rows.append(
            {
                "file_name": file_name or "-",
                "categories": categories[:12],
                "patterns": patterns[:40],
                "pattern_count": len(patterns),
            }
        )

    rows.sort(key=lambda row: (int(row.get("pattern_count") or 0), len(row.get("categories") or [])), reverse=True)
    return rows[:120]


def _extract_matched_rules(report_data: dict) -> List[dict]:
    raw = report_data.get("matched_rules")
    if not isinstance(raw, list):
        return []

    merged: Dict[str, dict] = {}

    def ensure_rule(rule_name: str) -> dict:
        key = _normalize_inline_text(str(rule_name or "unknown_rule"))
        if key not in merged:
            merged[key] = {
                "name": key,
                "count": 0,
                "samples": [],
                "sample_set": set(),
            }
        return merged[key]

    for entry in raw:
        if isinstance(entry, str):
            normalized_entry = _normalize_inline_text(entry)
            row = ensure_rule(normalized_entry)
            if normalized_entry not in row["sample_set"]:
                row["sample_set"].add(normalized_entry)
                row["samples"].append({"pattern": normalized_entry, "offset": ""})
                row["count"] += 1
            continue

        if not isinstance(entry, dict):
            continue

        for rule_name, hits in entry.items():
            row = ensure_rule(rule_name)

            if isinstance(hits, list):
                if not hits:
                    continue
                for hit in hits:
                    pattern = ""
                    offset = ""
                    if isinstance(hit, dict):
                        pattern = str(hit.get("matched_pattern") or hit.get("pattern") or "").strip()
                        offset = _normalize_inline_text(str(hit.get("offset") or ""))
                    elif hit is not None:
                        pattern = _normalize_inline_text(str(hit))
                    pattern = _normalize_inline_text(pattern)

                    if not pattern:
                        continue
                    key = f"{offset}|{pattern}"
                    if key not in row["sample_set"]:
                        row["sample_set"].add(key)
                        row["samples"].append({"pattern": pattern, "offset": offset})
                        row["count"] += 1
            elif hits:
                pattern = _normalize_inline_text(str(hits))
                if pattern and pattern not in row["sample_set"]:
                    row["sample_set"].add(pattern)
                    row["samples"].append({"pattern": pattern, "offset": ""})
                    row["count"] += 1

    rows: List[dict] = []
    for row in merged.values():
        rows.append(
            {
                "name": row["name"],
                "count": int(row["count"]),
                "samples": row["samples"][:16],
            }
        )
    rows.sort(key=lambda item: item["count"], reverse=True)
    return rows


def _extract_mitre_rows(report_data: dict) -> List[dict]:
    raw = report_data.get("mitre_attack")
    if not isinstance(raw, dict):
        return []

    tactic_rows: List[dict] = []
    for tactic, techniques_raw in raw.items():
        tactic_name = _normalize_inline_text(str(tactic or ""))
        if not tactic_name:
            continue
        if not isinstance(techniques_raw, list):
            continue

        techniques: List[dict] = []
        total_score = 0
        for item in techniques_raw:
            if not isinstance(item, dict):
                continue
            technique_name = _normalize_inline_text(str(item.get("technique") or ""))
            if not technique_name:
                continue

            matched_apis: List[str] = []
            seen_api = set()
            api_raw = item.get("matched_apis")
            if isinstance(api_raw, list):
                for api in api_raw:
                    api_name = _normalize_inline_text(str(api or ""))
                    if not api_name:
                        continue
                    k = api_name.lower()
                    if k in seen_api:
                        continue
                    seen_api.add(k)
                    matched_apis.append(api_name)

            api_match_count = len(matched_apis)
            if api_match_count <= 0:
                continue
            total_score += api_match_count
            techniques.append(
                {
                    "technique": technique_name,
                    "tid": _normalize_inline_text(str(item.get("tid") or item.get("id") or "")),
                    # Keep score for backwards compatibility, but define it as API evidence count.
                    "score": api_match_count,
                    "api_match_count": api_match_count,
                    "matched_apis": matched_apis[:24],
                }
            )

        if not techniques:
            continue

        techniques.sort(key=lambda row: row["score"], reverse=True)
        tactic_rows.append(
            {
                "tactic": tactic_name,
                "technique_count": len(techniques),
                "score": total_score,
                "api_match_count": total_score,
                "techniques": techniques[:80],
            }
        )

    tactic_rows.sort(key=lambda row: (int(row.get("score") or 0), int(row.get("technique_count") or 0)), reverse=True)
    return tactic_rows[:24]


def _extract_permissions_section(report_data: dict) -> dict:
    out = {
        "available": False,
        "counts": {"dangerous": 0, "special": 0, "info": 0},
        "rows": [],
    }
    if not isinstance(report_data, dict):
        return out

    raw = report_data.get("permissions")
    if not isinstance(raw, list):
        summary = report_data.get("permission_summary")
        if isinstance(summary, dict):
            out["counts"] = {
                "dangerous": int(summary.get("dangerous") or 0),
                "special": int(summary.get("special") or 0),
                "info": int(summary.get("info") or 0),
            }
            out["available"] = any(int(v) > 0 for v in out["counts"].values())
        return out

    state_rank = {"dangerous": 3, "special": 2, "info": 1}
    merged: Dict[str, str] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        for perm_name, state_raw in item.items():
            perm = _normalize_inline_text(str(perm_name or ""))
            if not perm:
                continue

            state = _normalize_inline_text(str(state_raw or "")).lower()
            if state in ("risky", "dangerous"):
                norm_state = "dangerous"
            elif state == "special":
                norm_state = "special"
            else:
                norm_state = "info"

            prev = merged.get(perm)
            if not prev or state_rank[norm_state] > state_rank[prev]:
                merged[perm] = norm_state

    if not merged:
        summary = report_data.get("permission_summary")
        if isinstance(summary, dict):
            out["counts"] = {
                "dangerous": int(summary.get("dangerous") or 0),
                "special": int(summary.get("special") or 0),
                "info": int(summary.get("info") or 0),
            }
            out["available"] = any(int(v) > 0 for v in out["counts"].values())
        return out

    rows = []
    counts = {"dangerous": 0, "special": 0, "info": 0}
    for perm, state in merged.items():
        counts[state] += 1
        rows.append({"name": perm, "state": state, "state_label": state.capitalize()})

    rows.sort(key=lambda row: (-state_rank.get(str(row.get("state")), 0), str(row.get("name", "")).lower()))

    out["counts"] = counts
    out["rows"] = rows[:200]
    out["available"] = True
    return out


def _build_carved_panels(carved_list: list) -> List[dict]:
    """Build detailed_panels entries for each carved_executables triage entry."""
    panels: List[dict] = []
    for entry in carved_list:
        if not isinstance(entry, dict):
            continue
        triage = entry.get("triage") or {}
        fname = entry.get("filename") or "carved_executable"

        # Basic info: top-level fields + flattened triage metadata
        kv: List[dict] = []
        for k, label in (
            ("filename",          "File"),
            ("offset_hex",        "Offset"),
            ("size_bytes",        "Size (bytes)"),
        ):
            val = entry.get(k)
            if val is not None:
                kv.append({"key": label, "value": _safe_panel_text(val)})
        for k, label in (
            ("file_type",         "File Type"),
            ("mime_type",         "MIME Type"),
            ("architecture",      "Architecture"),
            ("subsystem",         "Subsystem"),
            ("compile_timestamp", "Compile Timestamp"),
            ("md5",               "MD5"),
            ("sha256",            "SHA-256"),
            ("imphash",           "Import Hash"),
        ):
            val = triage.get(k)
            if val:
                kv.append({"key": label, "value": _safe_panel_text(val)})
        if kv:
            panels.append({"title": f"Carved: {fname}", "kind": "kv", "count": len(kv), "rows": kv})

        # PE sections table
        pe_sections = triage.get("sections") or []
        if pe_sections and all(isinstance(s, dict) for s in pe_sections):
            cols = ["name", "raw_size", "entropy", "packed"]
            rows = [[_safe_panel_text(s.get(c)) for c in cols] for s in pe_sections]
            panels.append({"title": f"PE Sections: {fname}", "kind": "table",
                           "count": len(pe_sections), "columns": cols, "rows": rows})

        # Suspicious imports
        imports = triage.get("suspicious_imports") or []
        if imports:
            panels.append({"title": f"Suspicious Imports: {fname}", "kind": "list",
                           "count": len(imports), "items": [_safe_panel_text(i) for i in imports]})

        # Embedded IoCs
        for ioc_key, ioc_label in (
            ("embedded_urls",   "Embedded URLs"),
            ("embedded_ips",    "Embedded IPs"),
            ("embedded_emails", "Embedded Emails"),
        ):
            iocs = triage.get(ioc_key) or []
            if iocs:
                panels.append({"title": f"{ioc_label}: {fname}", "kind": "list",
                               "count": len(iocs), "items": [_safe_panel_text(i) for i in iocs]})

    return panels


def _build_detailed_panels(report_data: dict, skip_keys: Optional[set] = None) -> List[dict]:
    panels: List[dict] = []
    for key, value in report_data.items():
        if skip_keys and key in skip_keys:
            continue
        title = _labelize_key(str(key))

        if _is_scalar(value):
            continue

        if isinstance(value, list):
            if not value:
                continue

            if all(isinstance(item, dict) for item in value):
                col_set = OrderedDict()
                for row in value:
                    for col_key in row.keys():
                        col_set[str(col_key)] = True
                        if len(col_set) >= MAX_TABLE_COLS:
                            break
                    if len(col_set) >= MAX_TABLE_COLS:
                        break
                columns = list(col_set.keys())
                rows: List[List[str]] = []
                for row in value[:MAX_TABLE_ROWS]:
                    rows.append([_safe_panel_text(row.get(col)) for col in columns])

                panels.append(
                    {
                        "title": title,
                        "kind": "table",
                        "count": len(value),
                        "columns": columns,
                        "rows": rows,
                    }
                )
            else:
                items = [_safe_panel_text(item) for item in value[:MAX_PANEL_ITEMS]]
                panels.append(
                    {
                        "title": title,
                        "kind": "list",
                        "count": len(value),
                        "items": items,
                    }
                )
            continue

        if isinstance(value, dict):
            if not value:
                continue

            kv_rows: List[dict] = []
            for sub_key, sub_value in list(value.items())[:MAX_PANEL_ITEMS]:
                kv_rows.append({"key": str(sub_key), "value": _safe_panel_text(sub_value)})

            panels.append(
                {
                    "title": title,
                    "kind": "kv",
                    "count": len(value),
                    "rows": kv_rows,
                }
            )

    return panels


def _build_vt_section(report_data: dict) -> dict:
    empty = {
        "available": False,
        "summary": [],
        "verdict_stats": [],
        "threat_names": [],
        "threat_categories": [],
        "detections": [],
        "error": "",
    }

    vt_data: Optional[dict] = None
    nested = report_data.get("virustotal_file")
    if isinstance(nested, dict):
        vt_data = nested
    elif str(report_data.get("analysis_type") or "").strip().lower() == "vt_file":
        vt_data = report_data
    elif str(report_data.get("target_type") or "").strip().lower() == "virustotal_file":
        vt_data = report_data

    if not isinstance(vt_data, dict):
        return empty

    if str(vt_data.get("status") or "").strip().lower() == "unavailable":
        out = dict(empty)
        out["error"] = _fmt_value(vt_data.get("error") or "VirusTotal data is unavailable.")
        return out

    summary: List[dict] = []
    summary_fields = (
        ("Threat Label", "threat_label"),
        ("Detections", "detection_count"),
        ("Engines", "engine_count"),
        ("MD5", "hash_md5"),
        ("Generated At", "generated_at"),
    )
    for label, key in summary_fields:
        if key not in vt_data:
            continue
        value = vt_data.get(key)
        if value in ("", None):
            continue
        summary.append({"label": label, "value": _fmt_value(value)})

    stats_raw = vt_data.get("last_analysis_stats") or {}
    verdict_stats: List[dict] = []
    if isinstance(stats_raw, dict):
        stat_order = (
            ("malicious", "Malicious"),
            ("suspicious", "Suspicious"),
            ("undetected", "Undetected"),
            ("harmless", "Harmless"),
            ("timeout", "Timeout"),
            ("confirmed-timeout", "Confirmed Timeout"),
            ("failure", "Failure"),
            ("type-unsupported", "Type Unsupported"),
        )
        for key, label in stat_order:
            try:
                value = int(stats_raw.get(key) or 0)
            except (TypeError, ValueError):
                value = 0
            if value > 0:
                verdict_stats.append({"key": key, "label": label, "value": value})

    threat_names: List[dict] = []
    for item in vt_data.get("threat_names") or []:
        if not isinstance(item, dict):
            continue
        value = _fmt_value(item.get("value"))
        if value == "-":
            continue
        threat_names.append({"value": value, "count": int(item.get("count") or 0)})

    threat_categories: List[dict] = []
    for item in vt_data.get("threat_categories") or []:
        if not isinstance(item, dict):
            continue
        value = _fmt_value(item.get("value"))
        if value == "-":
            continue
        threat_categories.append({"value": value, "count": int(item.get("count") or 0)})

    detections: List[dict] = []
    for item in vt_data.get("detections") or []:
        if not isinstance(item, dict):
            continue
        engine = _fmt_value(item.get("engine"))
        result = _fmt_value(item.get("result"))
        if engine == "-" or result == "-":
            continue
        detections.append(
            {
                "engine": engine,
                "result": result,
                "category": _fmt_value(item.get("category")),
                "method": _fmt_value(item.get("method")),
            }
        )

    return {
        "available": bool(summary or verdict_stats or threat_names or threat_categories or detections),
        "summary": summary[:8],
        "verdict_stats": verdict_stats,
        "threat_names": threat_names[:12],
        "threat_categories": threat_categories[:12],
        "detections": detections[:80],
        "error": "",
    }


def build_frontend_payload(report_data: Optional[dict]) -> dict:
    if not isinstance(report_data, dict):
        return {
            "summary": [],
            "hashes": [],
            "categories": [],
            "permissions_section": {"available": False, "counts": {"dangerous": 0, "special": 0, "info": 0}, "rows": []},
            "windows_api_categories": [],
            "mitre_rows": [],
            "vt_threat_label": "",
            "vt_section": {
                "available": False,
                "summary": [],
                "verdict_stats": [],
                "threat_names": [],
                "threat_categories": [],
                "detections": [],
                "error": "",
            },
            "interesting_patterns": [],
            "source_pattern_rows": [],
            "matched_rules_rows": [],
            "sections": [],
            "metadata": [],
            "extra_panels": [],
            "detailed_panels": [],
            "script_analysis_section": {"available": False, "language": "", "vbe_encoded": False, "categories": [], "createobject_values": [], "shell_commands": [], "decoded_payload_hints": []},
            "archive_section": {"available": False, "archive_type": "", "member_count": 0, "file_count": 0, "directory_count": 0, "members": []},
            "packer_section": {"available": False, "packed": False, "yara_evidence_only": False, "string_hits_count": 0},
            "ioc_section": {"available": False, "urls": [], "domains": [], "ips": [], "emails": [], "hashes": [], "file_paths": []},
            "language_section": {"available": False, "primary_language": "", "extension_hint": "", "relative_score_share": 0.0, "evidence_basis": "", "pattern_hits": 0, "strong_hits": 0, "weak_hits": 0, "matched_patterns": []},
            "ai_output": "",
            "ai_iocs": [],
            "ai_context": [],
        }

    hashes: List[dict] = []
    consumed_keys = {
    "target_type", "filename", "sha256", "report_type",
    "ml_conf", "final_risk", "behavior_score", "packer_score",
    "ml_integrated", "ml_integration_mode", "ml_scan_error",
    "sections", "mitre_attack", "notes", "family", "categorized_findings"
    }
    ai_output = ""
    ai_iocs: List[dict] = []
    ai_context: List[dict] = []
    vt_section = _build_vt_section(report_data)
    if isinstance(report_data.get("output"), str):
        ai_output = report_data.get("output", "").strip()
        consumed_keys.add("output")

    normalized_ioc_key = "extracted_iocs" if isinstance(report_data.get("extracted_iocs"), dict) else "llm_extracted_iocs"
    if isinstance(report_data.get(normalized_ioc_key), dict):
        if normalized_ioc_key == "llm_extracted_iocs":
            consumed_keys.add("llm_extracted_iocs")
        ioc_dict = report_data.get(normalized_ioc_key) or {}
        for kind, values in ioc_dict.items():
            if isinstance(values, list):
                if len(values) == 0:
                    continue
                ai_iocs.append(
                    {
                        "kind": _ioc_kind_label(str(kind)),
                        "count": len(values),
                        "values": [_fmt_value(v) for v in values[:40]],
                    }
                )
            elif values:
                ai_iocs.append(
                    {
                        "kind": _ioc_kind_label(str(kind)),
                        "count": 1,
                        "values": [_fmt_value(values)],
                    }
                )

    for key in ("analysis_type", "engine", "model", "generated_at", "report_file"):
        value = report_data.get(key)
        if value:
            ai_context.append({"label": _labelize_key(key), "value": _fmt_value(value)})
            consumed_keys.add(key)

    windows_api_categories: List[dict] = []
    categories_obj = report_data.get("categories")
    if isinstance(categories_obj, dict):
        for cat_name, cat_values in categories_obj.items():
            if not isinstance(cat_values, list) or not cat_values:
                continue
            if all(isinstance(item, str) for item in cat_values):
                windows_api_categories.append(
                    {
                        "name": str(cat_name),
                        "count": len(cat_values),
                        "apis": [str(api) for api in cat_values[:60]],
                    }
                )
        windows_api_categories.sort(key=lambda row: row["count"], reverse=True)

    interesting_patterns = _extract_interesting_patterns(report_data)
    source_pattern_rows = _extract_source_pattern_rows(report_data)
    matched_rules_rows = _extract_matched_rules(report_data)
    mitre_rows = _extract_mitre_rows(report_data)
    permissions_section = _extract_permissions_section(report_data)

    # VBScript/VBA script analysis section
    script_analysis_section: dict = {"available": False, "language": "", "vbe_encoded": False, "categories": [], "createobject_values": [], "shell_commands": [], "decoded_payload_hints": []}
    sa = report_data.get("script_analysis")
    if isinstance(sa, dict):
        consumed_keys.add("script_analysis")
        script_analysis_section["available"] = True
        script_analysis_section["language"] = str(sa.get("language") or "")
        script_analysis_section["vbe_encoded"] = bool(sa.get("vbe_encoded"))
        cats_raw = sa.get("categories") or {}
        if isinstance(cats_raw, dict):
            for cat_name, cat_hits in cats_raw.items():
                if isinstance(cat_hits, list) and cat_hits:
                    script_analysis_section["categories"].append({
                        "name": str(cat_name),
                        "count": len(cat_hits),
                        "hits": [str(h) for h in cat_hits[:50]],
                    })
        for field in ("createobject_values", "shell_commands", "decoded_payload_hints"):
            val = sa.get(field)
            if isinstance(val, list):
                script_analysis_section[field] = [str(v) for v in val[:50]]

    archive_section = {"available": False, "archive_type": "", "member_count": 0, "file_count": 0, "directory_count": 0, "members": []}
    if report_data.get("target_type") == "archive" or "archive_contents" in report_data:
        archive_contents = report_data.get("archive_contents") or []
        archive_section = {
            "available": True,
            "archive_type": str(report_data.get("archive_type") or ""),
            "member_count": int(report_data.get("archive_member_count") or len(archive_contents)),
            "file_count": int(report_data.get("archive_file_count") or 0),
            "directory_count": int(report_data.get("archive_directory_count") or 0),
            "members": [
                {"name": str(item.get("name") or ""), "size": int(item.get("size") or 0), "is_dir": bool(item.get("is_dir"))}
                for item in archive_contents[:80] if isinstance(item, dict)
            ],
        }

    packer_section = {"available": False, "packed": False, "yara_evidence_only": False, "string_hits_count": 0}
    if report_data.get("target_type") == "packer_detection" or "packed" in report_data:
        packer_section = {
            "available": True,
            "packed": bool(report_data.get("packed")),
            "yara_evidence_only": bool(report_data.get("yara_evidence_only")),
            "string_hits_count": int(report_data.get("string_hits_count") or 0),
        }

    raw_iocs = report_data.get("extracted_iocs") if isinstance(report_data.get("extracted_iocs"), dict) else report_data.get("llm_extracted_iocs")
    raw_iocs = raw_iocs if isinstance(raw_iocs, dict) else {}
    ioc_section = {
        "available": bool(report_data.get("target_type") == "domain_ioc" or raw_iocs or report_data.get("extracted_urls") or report_data.get("extracted_ips") or report_data.get("extracted_emails")),
        "urls": [str(v) for v in (raw_iocs.get("urls") or report_data.get("extracted_urls") or [])[:100]],
        "domains": [str(v) for v in (raw_iocs.get("domains") or report_data.get("extracted_domains") or [])[:100]],
        "ips": [str(v) for v in (raw_iocs.get("ips") or report_data.get("extracted_ips") or [])[:100]],
        "emails": [str(v) for v in (raw_iocs.get("emails") or report_data.get("extracted_emails") or [])[:100]],
        "hashes": [str(v) for v in (raw_iocs.get("hashes") or [])[:100]],
        "file_paths": [str(v) for v in (raw_iocs.get("file_paths") or [])[:100]],
    }
    if report_data.get("target_type") == "domain_ioc":
        consumed_keys.update({"extracted_iocs", "extracted_domains", "extracted_ips", "extracted_emails"})

    language_section = {"available": False, "primary_language": "", "extension_hint": "", "relative_score_share": 0.0, "evidence_basis": "", "pattern_hits": 0, "strong_hits": 0, "weak_hits": 0, "matched_patterns": []}
    if report_data.get("target_type") == "language_detection" or "primary_language" in report_data:
        detected_languages = report_data.get("detected_languages") or []
        primary = detected_languages[0] if detected_languages and isinstance(detected_languages[0], dict) else {}
        relative_share = primary.get("relative_score_share", primary.get("confidence", report_data.get("primary_relative_score_share", 0.0)))
        evidence_basis = str(primary.get("evidence_basis") or report_data.get("primary_evidence_basis") or "")
        if not evidence_basis:
            pattern_hits = int(primary.get("pattern_hits") or 0)
            ext_used = bool(primary.get("extension_hint"))
            evidence_basis = "patterns_and_extension" if pattern_hits and ext_used else ("patterns_only" if pattern_hits else ("extension_only" if ext_used else "score_only"))
        language_section = {
            "available": True,
            "primary_language": str(report_data.get("primary_language") or primary.get("language") or ""),
            "extension_hint": str(report_data.get("extension_hint") or ""),
            "relative_score_share": round(float(relative_share or 0.0), 2),
            "evidence_basis": evidence_basis,
            "pattern_hits": int(primary.get("pattern_hits") or 0),
            "strong_hits": int(primary.get("strong_hits") or 0),
            "weak_hits": int(primary.get("weak_hits") or 0),
            "matched_patterns": [str(v) for v in (primary.get("matched_patterns") or [])[:24]],
        }

    for key, label in (("hash_md5", "MD5"), ("hash_sha1", "SHA1"), ("hash_sha256", "SHA256"), ("imphash", "Imphash")):
        if report_data.get(key):
            hashes.append({"label": label, "value": str(report_data.get(key))})
            consumed_keys.add(key)

    sections: List[dict] = []
    interesting_keys = (
        ("linked_dll", "Linked DLLs"),
        ("libraries", "Libraries"),
        ("dynamic_libraries", "Dynamic Libraries"),
        ("attachments", "Attachments"),
        ("embedded_files", "Embedded Files"),
        ("extracted_urls", "Extracted URLs"),
        ("segments", "Segments"),
        ("sections", "Sections"),
    )

    for key, title in interesting_keys:
        if key not in report_data:
            continue
        value = report_data.get(key)
        count = _count_items(value)
        if count == 0:
            continue
        consumed_keys.add(key)
        sections.append(
            {
                "title": title,
                "count": count,
                "items": _preview_items(value),
            }
        )

    if "golang" in report_data and not _has_meaningful_golang_data(report_data.get("golang")):
        consumed_keys.add("golang")

    # --- PCAP-specific handling ---
    # http_requests and suspicious_connections are lists-of-dicts; they render
    # as proper tables inside detailed_panels, so suppress the coarser
    # extra_panels preview to avoid duplicate display.
    pcap_panels: List[dict] = []
    for _pcap_list_key in ("http_requests", "suspicious_connections"):
        if _pcap_list_key in report_data:
            consumed_keys.add(_pcap_list_key)
    # carved_executables carries nested triage data that the generic table
    # renderer can't display cleanly; delegate to the dedicated builder.
    if "carved_executables" in report_data:
        consumed_keys.add("carved_executables")
        _carved = report_data.get("carved_executables") or []
        if isinstance(_carved, list):
            pcap_panels = _build_carved_panels(_carved)

    metadata: List[dict] = []
    extra_panels: List[dict] = []
    for key, value in report_data.items():
        if key in consumed_keys:
            continue

        if isinstance(value, (str, int, float, bool)):
            if value in ("", None):
                continue
            metadata.append({"label": _labelize_key(str(key)), "value": _fmt_value(value)})
            continue

        if isinstance(value, list):
            if not value:
                continue
            extra_panels.append(
                {
                    "title": _labelize_key(str(key)),
                    "count": len(value),
                    "items": _preview_items(value, limit=24),
                }
            )
            continue

        if isinstance(value, dict):
            if not value:
                continue
            extra_panels.append(
                {
                    "title": _labelize_key(str(key)),
                    "count": len(value),
                    "items": _preview_items(value, limit=24),
                }
            )
        
        # Add this section to your report_ui builder
    if "notes" in report_data and report_data["notes"]:
        extra_panels.append({ # Use extra_panels, not report_ui["extra_panels"] here
            "title": "Trust & Static Heuristic Notes",
            "kind": "list",
            "items": [str(n) for n in report_data["notes"]]
        })

    metadata = metadata[:16]
   
    
    # ---------------------------------------------------
    # Merge behavioral panels at the start of the list
    # Adding 'mitre_attack' here prevents it from rendering as a raw JSON box
    duplicate_section_keys = {key for key, _title in interesting_keys if key in report_data}
    detailed_skip_keys = {"carved_executables", "mitre_attack", "llm_extracted_iocs"} | duplicate_section_keys
    if report_data.get("target_type") == "domain_ioc":
        detailed_skip_keys |= {"extracted_iocs", "extracted_domains", "extracted_ips", "extracted_emails"}
    all_detailed_panels = _build_detailed_panels(report_data, skip_keys=detailed_skip_keys) + pcap_panels

    return {
        "summary": build_summary(report_data),
        "ml_available": "ml_conf" in report_data,
        "ml_raw": int(round(float(report_data.get("ml_conf", 0)) * 100)),
        "behavior_score_val": float(report_data.get("behavior_score", 0) or 0),
        "packer_score_val": float(report_data.get("packer_score", 0) or 0),
        "final_risk_val": (
            int(min(100, max(0, float(report_data.get("final_risk")))))
            if report_data.get("final_risk") is not None
            else None
        ),
        "heuristic_notes": [str(n) for n in (report_data.get("notes") or [])],
        "hashes": hashes,
        "categories": _extract_categories(report_data),
        "permissions_section": permissions_section,
        "windows_api_categories": windows_api_categories,
        "mitre_rows": mitre_rows,
        "vt_section": vt_section,
        "interesting_patterns": interesting_patterns,
        "source_pattern_rows": source_pattern_rows,
        "matched_rules_rows": matched_rules_rows,
        "sections": sections,
        "metadata": metadata,
        "extra_panels": extra_panels,
        "detailed_panels": all_detailed_panels, # Combined list
        "script_analysis_section": script_analysis_section,
        "archive_section": archive_section,
        "packer_section": packer_section,
        "ioc_section": ioc_section,
        "language_section": language_section,
        "ai_output": ai_output,
        "ai_iocs": ai_iocs,
        "ai_context": ai_context,
    }

def _vt_api_key_path() -> Path:
    return Path.home() / "sc0pe_Base" / "sc0pe_VT_apikey.txt"


def _load_vt_api_key() -> str:
    key_file = _vt_api_key_path()
    if not key_file.exists():
        raise RuntimeError("VirusTotal API key not found. Run: python3 Malsecure.py --key_init")
    key = key_file.read_text(encoding="utf-8").splitlines()[0].strip()
    if not key:
        raise RuntimeError("VirusTotal API key file is empty. Run: python3 Malsecure.py --key_init")
    if len(key) != 64:
        raise RuntimeError("VirusTotal API key looks invalid (expected 64 chars).")
    return key


def _md5_file(path: Path) -> str:
    md5 = hashlib.md5()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            md5.update(chunk)
    return md5.hexdigest()


def _build_vt_report(vt_data: dict, sample_path: Path, target_hash: str) -> dict:
    data = vt_data.get("data") or {}
    attrs = data.get("attributes") or {}
    threat_class = attrs.get("popular_threat_classification") or {}

    threat_categories = []
    for item in threat_class.get("popular_threat_category") or []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        threat_categories.append({"value": value, "count": int(item.get("count") or 0)})

    threat_names = []
    for item in threat_class.get("popular_threat_name") or []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        threat_names.append({"value": value, "count": int(item.get("count") or 0)})

    detections = []
    last_results = attrs.get("last_analysis_results") or {}
    if isinstance(last_results, dict):
        for engine, row in last_results.items():
            if not isinstance(row, dict):
                continue
            result = row.get("result")
            if result is None:
                continue
            detections.append(
                {
                    "engine": str(engine),
                    "result": str(result),
                    "category": str(row.get("category") or ""),
                    "method": str(row.get("method") or ""),
                }
            )
    detections.sort(key=lambda item: item["engine"].lower())

    ids_reports = []
    for row in attrs.get("crowdsourced_ids_results") or []:
        if not isinstance(row, dict):
            continue
        alert_ctx = row.get("alert_context") or []
        if isinstance(alert_ctx, list) and alert_ctx:
            ctx = alert_ctx[0] if isinstance(alert_ctx[0], dict) else {}
        else:
            ctx = {}
        ids_reports.append(
            {
                "severity": str(row.get("alert_severity") or ""),
                "rule_category": str(row.get("rule_category") or ""),
                "rule_source": str(row.get("rule_source") or ""),
                "src_ip": str(ctx.get("src_ip") or ""),
                "src_port": str(ctx.get("src_port") or ""),
                "dest_ip": str(ctx.get("dest_ip") or ""),
                "dest_port": str(ctx.get("dest_port") or ""),
            }
        )

    return {
        "analysis_type": "vt_file",
        "filename": sample_path.name,
        "hash_md5": target_hash,
        "target_type": "virustotal_file",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "threat_label": str(threat_class.get("suggested_threat_label") or ""),
        "detection_count": len(detections),
        "engine_count": len(last_results) if isinstance(last_results, dict) else 0,
        "last_analysis_stats": attrs.get("last_analysis_stats") or {},
        "threat_categories": threat_categories,
        "threat_names": threat_names,
        "detections": detections,
        "ids_reports": ids_reports,
        "ids_stats": attrs.get("crowdsourced_ids_stats") or {},
    }


def execute_vtfile_scan(sample_path: Path, command_display: str) -> dict:
    started = time.perf_counter()
    try:
        api_key = _load_vt_api_key()
    except Exception as exc:  # noqa: BLE001
        return {
            "exit_code": 2,
            "timed_out": False,
            "duration": round(time.perf_counter() - started, 2),
            "command_display": command_display,
            "report_expected": True,
            "report_path": "",
            "ai_report_path": "",
            "error_message": str(exc),
        }

    target_hash = _md5_file(sample_path)
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{target_hash}",
            headers={"x-apikey": api_key},
            timeout=60,
        )
    except requests.RequestException as exc:
        return {
            "exit_code": 1,
            "timed_out": False,
            "duration": round(time.perf_counter() - started, 2),
            "command_display": command_display,
            "report_expected": True,
            "report_path": "",
            "ai_report_path": "",
            "error_message": f"VirusTotal request failed: {exc}",
        }

    if resp.status_code == 404:
        return {
            "exit_code": 1,
            "timed_out": False,
            "duration": round(time.perf_counter() - started, 2),
            "command_display": command_display,
            "report_expected": True,
            "report_path": "",
            "ai_report_path": "",
            "error_message": "VirusTotal has no report for this file hash yet.",
        }

    if not resp.ok:
        detail = _trim_text(resp.text or "", 600)
        return {
            "exit_code": 1,
            "timed_out": False,
            "duration": round(time.perf_counter() - started, 2),
            "command_display": command_display,
            "report_expected": True,
            "report_path": "",
            "ai_report_path": "",
            "error_message": f"VirusTotal API error ({resp.status_code}): {detail}",
        }

    try:
        vt_data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return {
            "exit_code": 1,
            "timed_out": False,
            "duration": round(time.perf_counter() - started, 2),
            "command_display": command_display,
            "report_expected": True,
            "report_path": "",
            "ai_report_path": "",
            "error_message": f"Failed to parse VirusTotal response: {exc}",
        }

    report = _build_vt_report(vt_data, sample_path, target_hash)
    report_name = f"sc0pe_vt_{target_hash[:12]}_report.json"
    report_path = _unique_report_destination(_report_bucket_dir("vt"), report_name)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    try:
        rel_report_path = str(report_path.relative_to(BASE_DIR))
    except ValueError:
        rel_report_path = str(report_path)

    return {
        "exit_code": 0,
        "timed_out": False,
        "duration": round(time.perf_counter() - started, 2),
        "command_display": command_display,
        "report_expected": True,
        "report_path": rel_report_path,
        "report_data": report,
        "ai_report_path": "",
        "error_message": "",
    }


def _load_json_from_report(report_path: str) -> Optional[dict]:
    resolved = _resolve_report_path(report_path)
    if not resolved or not resolved.exists():
        return None
    try:
        data = json.loads(resolved.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(data, dict):
        return None
    return data


def _embed_vt_result_into_main_report(main_report_path: str, vt_result: dict) -> None:
    resolved = _resolve_report_path(main_report_path)
    if not resolved or not resolved.exists():
        return

    try:
        main_data = json.loads(resolved.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return
    if not isinstance(main_data, dict):
        return

    exit_code_raw = vt_result.get("exit_code")
    try:
        vt_exit_code = int(exit_code_raw) if exit_code_raw is not None else 1
    except (TypeError, ValueError):
        vt_exit_code = 1

    vt_payload: Optional[dict] = None
    if isinstance(vt_result.get("report_data"), dict):
        vt_payload = vt_result.get("report_data")

    vt_report_path = str(vt_result.get("report_path") or "")
    if vt_payload is None and vt_exit_code == 0 and vt_report_path:
        vt_payload = _load_json_from_report(vt_report_path)

    if not isinstance(vt_payload, dict):
        base_error = str(vt_result.get("error_message") or "").strip()
        if not base_error and vt_exit_code == 0:
            base_error = "VirusTotal scan finished but report payload could not be loaded."
        vt_payload = {
            "status": "unavailable",
            "error": base_error or "VirusTotal lookup did not return a report.",
        }

    main_data["virustotal_file"] = vt_payload
    try:
        resolved.write_text(json.dumps(main_data, indent=2), encoding="utf-8")
    except Exception:  # noqa: BLE001
        return



def _looks_like_pe_file(sample_path: Path) -> bool:
    """Return True when the uploaded sample has a PE/DOS MZ header."""
    try:
        with sample_path.open("rb") as handle:
            return handle.read(2) == b"MZ"
    except OSError:
        return False


def _detect_new_behavioral_report(before: Dict[Path, int]) -> Optional[Path]:
    candidates: List[Tuple[int, Path]] = []

    for path in REPORTS_ROOT.glob("sc0pe_behavior_report*.json"):
        if not path.exists():
            continue

        try:
            mtime_ns = path.stat().st_mtime_ns
        except OSError:
            continue

        if path not in before or mtime_ns > before[path]:
            candidates.append((mtime_ns, path))

    if not candidates:
        return None

    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _merge_integrated_ml_into_report(
    stored_report_path: str,
    ml_payload: dict,
) -> None:
    if not stored_report_path or not isinstance(ml_payload, dict):
        return

    resolved = _resolve_report_path(str(stored_report_path))
    if not resolved or not resolved.exists():
        return

    try:
        main_data = json.loads(resolved.read_text(encoding="utf-8"))
    except Exception:
        return

    if not isinstance(main_data, dict):
        return

    # Merge only the stable behavioral/ML fields used by the frontend.
    for key in (
        "target_type",
        "ml_conf",
        "behavior_score",
        "packer_score",
        "final_risk",
        "family",
        "vt_threat_label",
    ):
        if key in ml_payload:
            main_data[key] = ml_payload[key]

    existing_notes = main_data.get("notes")
    ml_notes = ml_payload.get("notes")

    merged_notes: List[str] = []

    for source in (existing_notes, ml_notes):
        if isinstance(source, list):
            for item in source:
                text = str(item).strip()
                if text and text not in merged_notes:
                    merged_notes.append(text)
        elif source:
            text = str(source).strip()
            if text and text not in merged_notes:
                merged_notes.append(text)

    if merged_notes:
        main_data["notes"] = merged_notes

    main_data["ml_integrated"] = True
    main_data["ml_integration_mode"] = "standard_pe"

    try:
        resolved.write_text(
            json.dumps(main_data, indent=2),
            encoding="utf-8",
        )
    except Exception:
        return


def _run_integrated_ml_scan(
    sample_path: Path,
    before_behavioral: Dict[Path, int],
    env: dict,
) -> Tuple[Optional[dict], str]:
    command = [
        PYTHON_BIN,
        str(ENTRYPOINT),
        "--file",
        str(sample_path),
        "--behavioral",
        "--report",
    ]

    try:
        completed = subprocess.run(
            command,
            cwd=str(REPORTS_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=ANALYSIS_TIMEOUT_SECONDS,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return None, "Integrated ML scan timed out."

    if completed.returncode != 0:
        log_output = "\n".join(
            part
            for part in (
                _to_text(completed.stdout).strip(),
                _to_text(completed.stderr).strip(),
            )
            if part
        ).strip()

        return (
            None,
            _trim_text(
                log_output
                or "Integrated ML analyzer process failed."
            ),
        )

    report_path = _detect_new_behavioral_report(before_behavioral)

    if not report_path:
        return None, "Integrated ML scan completed but no behavioral report was produced."

    try:
        payload = json.loads(
            report_path.read_text(encoding="utf-8")
        )
    except Exception as exc:
        return None, f"Integrated ML report parse error: {exc}"

    if not isinstance(payload, dict):
        return None, "Integrated ML report has an invalid structure."

    return payload, ""


SMART_DOC_EXTENSIONS = {
    ".pdf",
    ".rtf",
    ".doc",
    ".docx",
    ".docm",
    ".dot",
    ".dotm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".xlt",
    ".xltm",
    ".ppt",
    ".pptx",
    ".pptm",
    ".pps",
    ".ppsm",
    ".vbs",
    ".vbe",
    ".vba",
    ".vb",
    ".bas",
    ".cls",
    ".frm",
    ".one",
}

SMART_SCRIPT_EXTENSIONS = {
    ".vbs",
    ".vbe",
    ".vba",
    ".vb",
    ".bas",
    ".cls",
    ".frm",
}

SMART_ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".ace",
}


def _smart_auto_decision(
    sample_path: Path,
    original_name: str,
) -> dict:
    """
    Content-first Smart Auto routing.

    This is intentionally conservative:
    it selects only primary analyzers that MalTracer actually exposes
    and that can produce a structured report.

    Target routing:
      - PE/MZ -> Standard Analysis
      - PDF/RTF/OLE/Office/VB-family -> Document
      - ZIP/RAR/ACE -> Archive
      - unsupported/unknown -> no automatic route
    """
    extension = Path(original_name).suffix.lower()

    try:
        with sample_path.open("rb") as handle:
            head = handle.read(8192)
    except OSError as exc:
        return {
            "supported": False,
            "preset_key": "",
            "detected_type": "Unreadable file",
            "method": "read-error",
            "reason": f"Could not inspect file bytes: {exc}",
            "modules": [],
        }

    # --------------------------------------------------------
    # 1. Windows PE — content signature wins over file name.
    # --------------------------------------------------------
    if head.startswith(b"MZ"):
        return {
            "supported": True,
            "preset_key": "analyze",
            "detected_type": "Windows PE executable",
            "method": "content-signature",
            "reason": "MZ executable header detected.",
            "modules": [
                "Windows Static Analysis",
                "YARA / Static Evidence",
                "MITRE ATT&CK Mapping",
                "VirusTotal Hash Lookup",
                "EMBER ML Risk Scoring",
            ],
        }

    # --------------------------------------------------------
    # 2. PDF / RTF / legacy OLE Office.
    # --------------------------------------------------------
    if b"%PDF" in head[:1024]:
        return {
            "supported": True,
            "preset_key": "docs",
            "detected_type": "PDF document",
            "method": "content-signature",
            "reason": "PDF header detected.",
            "modules": [
                "Document Analysis",
                "Embedded Content / URL Checks",
                "YARA",
                "VirusTotal Hash Lookup",
            ],
        }

    if head.lstrip().startswith(b"{\\rtf"):
        return {
            "supported": True,
            "preset_key": "docs",
            "detected_type": "Rich Text Format document",
            "method": "content-signature",
            "reason": "RTF document header detected.",
            "modules": [
                "Document Analysis",
                "Exploit / Script Checks",
                "URL Extraction",
                "YARA",
                "VirusTotal Hash Lookup",
            ],
        }

    if head.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        return {
            "supported": True,
            "preset_key": "docs",
            "detected_type": "OLE / Compound Office document",
            "method": "content-signature",
            "reason": "Microsoft Compound File Binary header detected.",
            "modules": [
                "Document Analysis",
                "Macro / Embedded Content Checks",
                "IOC / URL Extraction",
                "YARA",
                "VirusTotal Hash Lookup",
            ],
        }

    # --------------------------------------------------------
    # 3. ZIP container.
    #    OOXML documents are ZIP containers too, therefore we
    #    inspect member names before deciding "Archive".
    # --------------------------------------------------------
    if zipfile.is_zipfile(sample_path):
        try:
            with zipfile.ZipFile(sample_path) as archive:
                names = {
                    str(name).replace("\\", "/").lower()
                    for name in archive.namelist()
                }
        except Exception:
            names = set()

        office_family = ""

        if any(name.startswith("word/") for name in names):
            office_family = "Microsoft Word OOXML document"
        elif any(name.startswith("xl/") for name in names):
            office_family = "Microsoft Excel OOXML document"
        elif any(name.startswith("ppt/") for name in names):
            office_family = "Microsoft PowerPoint OOXML document"

        if office_family or "[content_types].xml" in names:
            return {
                "supported": True,
                "preset_key": "docs",
                "detected_type": office_family or "OOXML Office document",
                "method": "container-structure",
                "reason": "Office document structure detected inside the ZIP container.",
                "modules": [
                    "Document Structure Analysis",
                    "Macro / Embedded Content Checks",
                    "IOC / URL Extraction",
                    "YARA",
                    "VirusTotal Hash Lookup",
                ],
            }

        return {
            "supported": True,
            "preset_key": "archive",
            "detected_type": "ZIP archive",
            "method": "container-signature",
            "reason": "Valid ZIP archive container detected.",
            "modules": [
                "Archive Inspection",
                "Nested File Enumeration",
                "Nested IOC / YARA Triage",
                "VirusTotal Hash Lookup",
            ],
        }

    # --------------------------------------------------------
    # 4. RAR / ACE signatures.
    # --------------------------------------------------------
    if (
        head.startswith(b"Rar!\x1A\x07\x00")
        or head.startswith(b"Rar!\x1A\x07\x01\x00")
    ):
        return {
            "supported": True,
            "preset_key": "archive",
            "detected_type": "RAR archive",
            "method": "content-signature",
            "reason": "RAR archive signature detected.",
            "modules": [
                "Archive Inspection",
                "Nested File Enumeration",
                "Nested IOC / YARA Triage",
                "VirusTotal Hash Lookup",
            ],
        }

    if b"**ACE**" in head[:64]:
        return {
            "supported": True,
            "preset_key": "archive",
            "detected_type": "ACE archive",
            "method": "content-signature",
            "reason": "ACE archive signature detected.",
            "modules": [
                "Archive Inspection",
                "Nested File Enumeration",
                "Nested IOC / YARA Triage",
            ],
        }

    # --------------------------------------------------------
    # 5. VB-family scripts have no reliable binary magic,
    #    so the existing supported extensions are used.
    # --------------------------------------------------------
    if extension in SMART_SCRIPT_EXTENSIONS:
        return {
            "supported": True,
            "preset_key": "docs",
            "detected_type": "VB / VBA-family script",
            "method": "supported-extension",
            "reason": f"Supported script extension detected: {extension}",
            "modules": [
                "VBScript / VBA Analysis",
                "URL Extraction",
                "YARA",
                "VirusTotal Hash Lookup",
            ],
        }

    # --------------------------------------------------------
    # 6. Conservative extension fallback for malformed/truncated
    #    files whose analyzer family is still unambiguous.
    # --------------------------------------------------------
    if extension in SMART_DOC_EXTENSIONS:
        return {
            "supported": True,
            "preset_key": "docs",
            "detected_type": "Document / script",
            "method": "supported-extension",
            "reason": f"Supported document extension detected: {extension}",
            "modules": [
                "Document Analysis",
                "YARA / IOC Checks",
                "VirusTotal Hash Lookup",
            ],
        }

    if extension in SMART_ARCHIVE_EXTENSIONS:
        return {
            "supported": True,
            "preset_key": "archive",
            "detected_type": "Archive",
            "method": "supported-extension",
            "reason": f"Supported archive extension detected: {extension}",
            "modules": [
                "Archive Inspection",
                "Nested IOC / YARA Triage",
            ],
        }

    return {
        "supported": False,
        "preset_key": "",
        "detected_type": "Unknown / unsupported primary type",
        "method": "no-safe-route",
        "reason": (
            "Smart Auto could not map this file to a supported primary "
            "analyzer from its content/signature. Use a manual profile "
            "if you intentionally want a targeted scan."
        ),
        "modules": [],
    }

def execute_preset(sample_path: Path, preset: AnalysisPreset, enable_ai: bool) -> dict:
    command_display = f"{PYTHON_BIN} {ENTRYPOINT} --file {sample_path} {' '.join(preset.args)}"

    if preset.args == ("--vtFile",):
        return execute_vtfile_scan(
            sample_path=sample_path,
            command_display=command_display,
        )

    vt_enabled_presets = {
        ("--analyze",),
        ("--docs",),
        ("--archive",),
        ("--behavioral",),
    }

    vt_future: Optional[concurrent.futures.Future] = None
    vt_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
    vt_result: Optional[dict] = None

    if preset.args in vt_enabled_presets:
        vt_command_display = (
            f"{PYTHON_BIN} {ENTRYPOINT} "
            f"--file {sample_path} --vtFile"
        )

        vt_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1
        )

        vt_future = vt_executor.submit(
            execute_vtfile_scan,
            sample_path=sample_path,
            command_display=vt_command_display,
        )

    before_reports = _report_snapshot()

    before_behavioral = {
        path: path.stat().st_mtime_ns
        for path in REPORTS_ROOT.glob(
            "sc0pe_behavior_report*.json"
        )
        if path.exists()
    }

    started = time.perf_counter()

    command = [
        PYTHON_BIN,
        str(ENTRYPOINT),
        "--file",
        str(sample_path),
        *preset.args,
    ]

    report_expected = bool(
        preset.report_default or enable_ai
    )

    if report_expected:
        command.append("--report")

    # NOTE:
    # Malsecure.py currently has no --ai CLI argument.
    # Do not append an unsupported argument here.
    # The EMBER ML pipeline is handled by --behavioral.

    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")

    timed_out = False

    try:
        completed = subprocess.run(
            command,
            cwd=str(REPORTS_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=ANALYSIS_TIMEOUT_SECONDS,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        timed_out = True

        completed = subprocess.CompletedProcess(
            args=command,
            returncode=124,
            stdout=_to_text(exc.stdout),
            stderr=(
                _to_text(exc.stderr)
                + "\nAnalysis timed out."
            ),
        )

    # Detect/store the primary report BEFORE running integrated ML,
    # otherwise the newer behavioral JSON could be mistaken for the
    # Standard Analysis report.
    changed_reports = _detect_new_reports(
        before_reports
    )

    report_path, ai_report_path = (
        _select_report_paths(
            changed_reports,
            ai_enabled=False,
        )
    )

    stored_report_path = _store_generated_report(
        report_path,
        bucket="main",
    )

    stored_ai_report_path = _store_generated_report(
        ai_report_path,
        bucket="ai",
    )

    # Existing standalone behavioral preset fallback.
    if (
        preset.args == ("--behavioral",)
        and not stored_report_path
    ):
        newest = _detect_new_behavioral_report(
            before_behavioral
        )

        if newest:
            stored_report_path = _store_generated_report(
                newest,
                bucket="main",
            )

    # --------------------------------------------------------
    # STANDARD ANALYSIS + EMBER ML INTEGRATION
    # --------------------------------------------------------
    # ML is meaningful for PE files. Documents/archives keep their
    # dedicated analyzers and do not get a fake/inapplicable PE score.
    integrated_ml_attempted = (
        preset.args == ("--analyze",)
        and _looks_like_pe_file(sample_path)
        and completed.returncode == 0
        and not timed_out
        and bool(stored_report_path)
    )

    integrated_ml_error = ""

    if integrated_ml_attempted:
        ml_payload, integrated_ml_error = (
            _run_integrated_ml_scan(
                sample_path=sample_path,
                before_behavioral=before_behavioral,
                env=env,
            )
        )

        if isinstance(ml_payload, dict):
            _merge_integrated_ml_into_report(
                str(stored_report_path),
                ml_payload,
            )

    duration = round(
        time.perf_counter() - started,
        2,
    )

    log_output = "\n".join(
        part
        for part in (
            _to_text(completed.stdout).strip(),
            _to_text(completed.stderr).strip(),
        )
        if part
    ).strip()

    error_message = ""

    if timed_out:
        error_message = "Analysis timed out."
    elif completed.returncode != 0:
        error_message = _trim_text(
            log_output
            or "Analyzer process failed."
        )
    elif report_expected and not stored_report_path:
        error_message = (
            "Analysis finished but no report file was produced."
        )

    # Integrated ML is supplemental to Standard Analysis.
    # A model failure must not discard otherwise valid static results.
    if integrated_ml_error and stored_report_path:
        resolved = _resolve_report_path(
            str(stored_report_path)
        )

        if resolved and resolved.exists():
            try:
                main_data = json.loads(
                    resolved.read_text(
                        encoding="utf-8"
                    )
                )

                if isinstance(main_data, dict):
                    main_data["ml_integrated"] = False
                    main_data["ml_scan_error"] = (
                        integrated_ml_error
                    )

                    resolved.write_text(
                        json.dumps(
                            main_data,
                            indent=2,
                        ),
                        encoding="utf-8",
                    )
            except Exception:
                pass

    if vt_future is not None:
        try:
            vt_result = vt_future.result()
        except Exception as exc:
            vt_result = {
                "exit_code": 1,
                "timed_out": False,
                "duration": 0.0,
                "command_display": "",
                "report_expected": True,
                "report_path": "",
                "ai_report_path": "",
                "error_message": (
                    "VirusTotal background scan error: "
                    f"{exc}"
                ),
            }
        finally:
            if vt_executor is not None:
                vt_executor.shutdown(wait=False)

    # Embed VT into Standard/Document/Archive reports.
    if (
        preset.args in vt_enabled_presets
        and preset.args != ("--behavioral",)
        and stored_report_path
        and isinstance(vt_result, dict)
    ):
        _embed_vt_result_into_main_report(
            stored_report_path,
            vt_result,
        )

    vt_threat_label = ""

    if (
        preset.args == ("--behavioral",)
        and isinstance(vt_result, dict)
    ):
        vt_payload = (
            vt_result.get("report_data")
            or {}
        )

        vt_threat_label = str(
            vt_payload.get("threat_label")
            or ""
        ).strip()

    return {
        "exit_code": int(completed.returncode),
        "timed_out": timed_out,
        "duration": duration,
        "command_display": " ".join(
            _to_text(item)
            for item in command
        ),
        "report_expected": report_expected,
        "report_path": stored_report_path,
        "ai_report_path": stored_ai_report_path,
        "error_message": error_message,
        "vt_threat_label": vt_threat_label,
        "ml_integrated": bool(
            integrated_ml_attempted
            and not integrated_ml_error
        ),
        "ml_error_message": integrated_ml_error,
    }


def _prune_history_locked() -> None:
    if len(JOBS) <= MAX_JOB_HISTORY:
        return

    removable = [
        (job_id, job)
        for job_id, job in JOBS.items()
        if job.get("status") in {"completed", "failed"}
    ]
    removable.sort(key=lambda pair: float(pair[1].get("finished_at") or 0.0))

    target_remove_count = max(0, len(JOBS) - MAX_JOB_HISTORY)
    for job_id, _job in removable[:target_remove_count]:
        JOBS.pop(job_id, None)


def _queue_worker() -> None:
    while True:
        job_id = JOB_QUEUE.get()
        sample_to_cleanup: Optional[Path] = None
        try:
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if not job:
                    continue
                job["status"] = "running"
                job["started_at"] = time.time()
                job["updated_at"] = time.time()
                preset_key = str(job["preset_key"])
                enable_ai = bool(job["enable_ai"])
                sample_to_cleanup = Path(str(job["sample_path"]))

            preset = PRESETS.get(preset_key)
            if preset is None:
                result = {
                    "exit_code": 2,
                    "timed_out": False,
                    "duration": 0.0,
                    "command_display": "",
                    "report_expected": False,
                    "report_path": "",
                    "ai_report_path": "",
                    "error_message": "Invalid analysis mode.",
                }
            else:
                result = execute_preset(
                    sample_path=sample_to_cleanup,
                    preset=preset,
                    enable_ai=enable_ai,
                )

            now_ts = time.time()
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if not job:
                    continue

                # Update base job metrics from the execution result
                job["exit_code"] = int(result["exit_code"])
                job["timed_out"] = bool(result["timed_out"])
                job["duration"] = float(result["duration"])
                job["command_display"] = str(result["command_display"])
                job["report_expected"] = bool(result["report_expected"])

                job["exit_code"] = int(result["exit_code"])
                job["timed_out"] = bool(result["timed_out"])
                job["duration"] = float(result["duration"])
                job["command_display"] = str(result["command_display"])
                job["report_expected"] = bool(result["report_expected"])

                job["report_path"] = str(result.get("report_path") or "")
                job["vt_threat_label"] = str(result.get("vt_threat_label") or "")

                report_data = _load_json_from_report(job["report_path"])
                if isinstance(report_data, dict) and "final_risk" in report_data:
                    try:
                        job["final_risk"] = float(report_data.get("final_risk"))
                    except (TypeError, ValueError):
                        job["final_risk"] = None
                else:
                    job["final_risk"] = None

                job["ai_report_path"] = str(result.get("ai_report_path") or "")
                job["error_message"] = str(result.get("error_message") or "")
                job["finished_at"] = now_ts
                job["updated_at"] = now_ts

                missing_expected_report = (
                    bool(result.get("report_expected"))
                    and not bool(job["report_path"])
                )

                if (
                    result["exit_code"] == 0
                    and not result["timed_out"]
                    and not missing_expected_report
                ):
                    job["status"] = "completed"
                else:
                    job["status"] = "failed"

                    if (
                        missing_expected_report
                        and not job["error_message"]
                    ):
                        job["error_message"] = (
                            "Analysis finished but no report file was produced."
                        )

                _prune_history_locked()

        except Exception as exc:  # noqa: BLE001
            now_ts = time.time()
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if job:
                    job["status"] = "failed"
                    job["error_message"] = f"Worker error: {exc}"
                    job["finished_at"] = now_ts
                    job["updated_at"] = now_ts
        finally:
            if sample_to_cleanup:
                try:
                    sample_to_cleanup.unlink(missing_ok=True)
                except OSError:
                    pass
            JOB_QUEUE.task_done()


def _ensure_worker() -> None:
    global WORKER_THREAD
    if WORKER_THREAD and WORKER_THREAD.is_alive():
        return
    WORKER_THREAD = threading.Thread(target=_queue_worker, daemon=True, name="sc0pe-web-worker")
    WORKER_THREAD.start()


def _queue_stats() -> dict:
    with JOBS_LOCK:
        queued = sum(1 for job in JOBS.values() if job.get("status") == "queued")
        running = sum(1 for job in JOBS.values() if job.get("status") == "running")
        return {
            "queued": queued,
            "running": running,
            "total": len(JOBS),
        }


def _job_list_snapshot(limit: int = 50) -> List[dict]:
    with JOBS_LOCK:
        jobs_sorted = sorted(JOBS.values(), key=lambda item: int(item.get("sequence", 0)), reverse=True)
        queued_sorted = sorted(
            (item for item in JOBS.values() if item.get("status") == "queued"),
            key=lambda item: int(item.get("sequence", 0)),
        )
        queue_pos_map = {str(item.get("id")): idx + 1 for idx, item in enumerate(queued_sorted)}

        rows: List[dict] = []
        for item in jobs_sorted[:limit]:
            job_id = str(item.get("id"))
            rows.append(
                {
                    "id": job_id,
                    "sample_name": str(item.get("sample_name", "-")),
                    "preset_label": str(item.get("preset_label", "-")),
                    "smart_auto": bool(item.get("smart_auto", False)),
                    "auto_detected_type": str(item.get("auto_detected_type", "")),
                    "auto_detection_reason": str(item.get("auto_detection_reason", "")),
                    "auto_detection_method": str(item.get("auto_detection_method", "")),
                    "auto_modules": list(item.get("auto_modules") or []),
                    "status": str(item.get("status", "queued")),
                    "duration": item.get("duration"),
                    "final_risk": item.get("final_risk"),
                    "queue_position": queue_pos_map.get(job_id),
                    "created_at_text": _ts_to_text(item.get("created_at")),
                    "started_at_text": _ts_to_text(item.get("started_at")),
                    "finished_at_text": _ts_to_text(item.get("finished_at")),
                }
            )

    return rows


def _job_snapshot(job_id: str) -> Optional[dict]:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return None

        snapshot = copy.deepcopy(job)
        queued_jobs = [item for item in JOBS.values() if item.get("status") == "queued"]

        if snapshot.get("status") == "queued":
            ahead = sum(1 for item in queued_jobs if int(item.get("sequence", 0)) < int(snapshot.get("sequence", 0)))
            snapshot["queue_position"] = ahead + 1
        elif snapshot.get("status") == "running":
            snapshot["queue_position"] = 0
        else:
            snapshot["queue_position"] = None

        snapshot["queued_total"] = len(queued_jobs)
        snapshot["running_total"] = sum(1 for item in JOBS.values() if item.get("status") == "running")

    snapshot["created_at_text"] = _ts_to_text(snapshot.get("created_at"))
    snapshot["started_at_text"] = _ts_to_text(snapshot.get("started_at"))
    snapshot["finished_at_text"] = _ts_to_text(snapshot.get("finished_at"))
    return snapshot


_ensure_worker()


@app.get("/")
def api_root():
    """Backend status endpoint. The MalTracer UI runs on React/Vite."""
    return jsonify(
        {
            "service": "MalTracer Backend API",
            "status": "ok",
            "ui": "http://localhost:5173/",
        }
    )


@app.post("/api/smart-analyze")
def smart_analyze_api():
    """
    JSON-only Smart Auto submission endpoint.
    This endpoint never redirects to Flask HTML.
    """
    global JOB_SEQUENCE

    sample = request.files.get("sample")

    if sample is None or not sample.filename:
        return jsonify({
            "error": "Please select a file."
        }), 400

    safe_name = secure_filename(sample.filename)

    if not safe_name:
        return jsonify({
            "error": "Invalid file name."
        }), 400

    unique_name = (
        f"{uuid.uuid4().hex[:10]}_{safe_name}"
    )
    sample_path = UPLOAD_DIR / unique_name
    sample.save(sample_path)

    decision = _smart_auto_decision(
        sample_path=sample_path,
        original_name=safe_name,
    )

    if not decision.get("supported"):
        try:
            sample_path.unlink(missing_ok=True)
        except OSError:
            pass

        return jsonify({
            "error": str(
                decision.get("reason")
                or "Smart Auto could not select a supported analyzer."
            ),
            "detected_type": str(
                decision.get("detected_type", "")
            ),
            "detection_method": str(
                decision.get("method", "")
            ),
        }), 415

    preset_key = str(
        decision.get("preset_key", "")
    )
    preset = PRESETS.get(preset_key)

    if preset is None:
        try:
            sample_path.unlink(missing_ok=True)
        except OSError:
            pass

        return jsonify({
            "error": "Smart Auto selected an unavailable backend preset."
        }), 500

    job_id = uuid.uuid4().hex
    now_ts = time.time()
    display_label = f"Smart Auto → {preset.label}"

    with JOBS_LOCK:
        JOB_SEQUENCE += 1

        JOBS[job_id] = {
            "id": job_id,
            "sequence": JOB_SEQUENCE,
            "status": "queued",
            "sample_name": safe_name,
            "sample_path": str(sample_path),
            "preset_key": preset_key,
            "preset_label": display_label,
            "resolved_preset_label": preset.label,
            "smart_auto": True,
            "auto_detected_type": str(
                decision.get("detected_type", "")
            ),
            "auto_detection_method": str(
                decision.get("method", "")
            ),
            "auto_detection_reason": str(
                decision.get("reason", "")
            ),
            "auto_modules": list(
                decision.get("modules", [])
            ),
            "enable_ai": False,
            "created_at": now_ts,
            "updated_at": now_ts,
            "started_at": None,
            "finished_at": None,
            "duration": None,
            "final_risk": None,
            "exit_code": None,
            "timed_out": False,
            "command_display": "",
            "report_expected": bool(
                preset.report_default
            ),
            "report_path": "",
            "ai_report_path": "",
            "error_message": "",
        }

    JOB_QUEUE.put(job_id)

    response = jsonify({
        "job_id": job_id,
        "status": "queued",
        "smart_auto": True,
        "selected_preset_key": preset_key,
        "selected_preset_label": preset.label,
        "display_label": display_label,
        "detected_type": str(
            decision.get("detected_type", "")
        ),
        "detection_method": str(
            decision.get("method", "")
        ),
        "detection_reason": str(
            decision.get("reason", "")
        ),
        "modules": list(
            decision.get("modules", [])
        ),
    })

    response.headers[
        "X-MalTracer-API"
    ] = "smart-auto-v1"

    return response, 202


@app.post("/analyze")
def run_analysis_route():
    global JOB_SEQUENCE

    sample = request.files.get("sample")

    smart_auto = (
        (request.form.get("smart_auto") or "")
        .strip()
        .lower()
        in {"1", "true", "on", "yes"}
    )

    requested_preset_key = (
        request.form.get("preset") or ""
    ).strip()

    enable_ai = (
        (request.form.get("enable_ai") or "")
        .strip()
        .lower()
        in {"1", "true", "on", "yes"}
    )

    def reject(message: str, status_code: int = 400):
        return jsonify({"error": message}), status_code

    if sample is None or not sample.filename:
        return reject("Please select a file.")

    safe_name = secure_filename(sample.filename)

    if not safe_name:
        return reject("Invalid file name.")

    # Manual mode can validate the preset before saving the upload.
    preset = None
    preset_key = requested_preset_key

    if not smart_auto:
        preset = PRESETS.get(preset_key)

        if preset is None:
            return reject(
                "Invalid analysis mode selected."
            )

    unique_name = (
        f"{uuid.uuid4().hex[:10]}_{safe_name}"
    )

    sample_path = UPLOAD_DIR / unique_name
    sample.save(sample_path)

    auto_decision = {
        "supported": False,
        "preset_key": "",
        "detected_type": "",
        "method": "",
        "reason": "",
        "modules": [],
    }

    if smart_auto:
        auto_decision = _smart_auto_decision(
            sample_path=sample_path,
            original_name=safe_name,
        )

        if not auto_decision.get("supported"):
            try:
                sample_path.unlink(missing_ok=True)
            except OSError:
                pass

            return reject(
                str(
                    auto_decision.get("reason")
                    or "Smart Auto could not select a supported analyzer."
                ),
                status_code=415,
            )

        preset_key = str(
            auto_decision.get("preset_key")
            or ""
        )

        preset = PRESETS.get(preset_key)

        if preset is None:
            try:
                sample_path.unlink(missing_ok=True)
            except OSError:
                pass

            return reject(
                "Smart Auto selected an unavailable backend preset.",
                status_code=500,
            )

    assert preset is not None

    job_id = uuid.uuid4().hex
    now_ts = time.time()

    display_label = (
        f"Smart Auto → {preset.label}"
        if smart_auto
        else preset.label
    )

    with JOBS_LOCK:
        JOB_SEQUENCE += 1

        JOBS[job_id] = {
            "id": job_id,
            "sequence": JOB_SEQUENCE,
            "status": "queued",
            "sample_name": safe_name,
            "sample_path": str(sample_path),

            # Actual analyzer chosen by the backend.
            "preset_key": preset_key,
            "preset_label": display_label,
            "resolved_preset_label": preset.label,

            # Smart Auto traceability.
            "smart_auto": smart_auto,
            "auto_detected_type": str(
                auto_decision.get(
                    "detected_type",
                    "",
                )
            ),
            "auto_detection_method": str(
                auto_decision.get(
                    "method",
                    "",
                )
            ),
            "auto_detection_reason": str(
                auto_decision.get(
                    "reason",
                    "",
                )
            ),
            "auto_modules": list(
                auto_decision.get(
                    "modules",
                    [],
                )
            ),

            "enable_ai": enable_ai,
            "created_at": now_ts,
            "updated_at": now_ts,
            "started_at": None,
            "finished_at": None,
            "duration": None,
            "final_risk": None,
            "exit_code": None,
            "timed_out": False,
            "command_display": "",
            "report_expected": bool(
                preset.report_default
                or enable_ai
            ),
            "report_path": "",
            "ai_report_path": "",
            "error_message": "",
        }

    JOB_QUEUE.put(job_id)

    return (
        jsonify(
            {
                "job_id": job_id,
                "status": "queued",
                "smart_auto": smart_auto,
                "selected_preset_key": preset_key,
                "selected_preset_label": preset.label,
                "display_label": display_label,
                "detected_type": str(
                    auto_decision.get(
                        "detected_type",
                        "",
                    )
                ),
                "detection_method": str(
                    auto_decision.get(
                        "method",
                        "",
                    )
                ),
                "detection_reason": str(
                    auto_decision.get(
                        "reason",
                        "",
                    )
                ),
                "modules": list(
                    auto_decision.get(
                        "modules",
                        [],
                    )
                ),
            }
        ),
        202,
    )


@app.get("/api/jobs")
def jobs_api():
    return jsonify(
        {
            "queue": _queue_stats(),
            "jobs": _job_list_snapshot(limit=100),
        }
    )

@app.get("/api/jobs/<job_id>")
def job_api(job_id: str):
    job = _job_snapshot(job_id)

    if not job:
        return jsonify({"error": "Job not found"}), 404

    report_view = _load_report_for_job(job)

    return jsonify({
        "job": job,
        "report_loaded": bool(report_view["report_loaded"]),
        "report_file_label": str(report_view["report_file_label"]),
        "report_load_error": str(report_view["report_load_error"]),
        "report_ui": report_view["report_ui"],
        "ai_loaded": bool(report_view["ai_loaded"]),
        "ai_file_label": str(report_view["ai_file_label"]),
        "ai_load_error": str(report_view["ai_load_error"]),
        "ai_ui": report_view["ai_ui"],
    })


@app.errorhandler(413)
def file_too_large(_error):
    return jsonify(
        {"error": f"File is too large. Maximum: {MAX_UPLOAD_MB} MB."}
    ), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055, debug=False)
