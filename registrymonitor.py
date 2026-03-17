"""
Author   : Sumit Dahiya (CDFE)
Project  : Windows Registry Change Monitoring System
Internship: Unified Mentor — Cybersecurity Track
Requires : Windows OS, Python 3.7+  (winreg is built-in on Windows)

Usage:
  python registrymonitor.py --baseline   → Capture fresh baseline (run first!)
  python registrymonitor.py --monitor    → Continuously monitor (Ctrl+C to stop)
  python registrymonitor.py --scan       → One-shot scan and report
  python registrymonitor.py --check      → Quick integrity hash check vs baseline
  python registrymonitor.py --reset      → Restore original clean baseline (discard rolling changes)
"""

import winreg
import json
import hashlib
import time
import logging
import sys
import shutil
from datetime import datetime
from pathlib import Path


# ======================================================
# CONFIGURATION
# ======================================================

BASELINE_FILE         = "registry_baseline.json"        # Rolling baseline (updated each scan)
CLEAN_BASELINE_FILE   = "registry_baseline_clean.json"  # Original clean baseline (never touched after --baseline)
LOG_FILE              = "registry_changes.log"
REPORT_FILE           = "registry_report.txt"
POLL_INTERVAL_SECONDS = 15

SUSPICIOUS_LOCATIONS = [
    "\\AppData\\",
    "\\Temp\\",
    "\\Public\\",
    "C:\\Users\\",
]


# ======================================================
# THREAT CLASSIFICATION TABLE
# ======================================================

THREAT_CLASSIFICATION = {
    # ── HKCU Run (current user persistence) ─────────────────────────────────
    ("HKCU_Run",     "ADDED"):    ("Persistence",         "MEDIUM"),
    ("HKCU_Run",     "MODIFIED"): ("Persistence",         "MEDIUM"),
    ("HKCU_Run",     "DELETED"):  ("Persistence",         "LOW"),
    ("HKCU_RunOnce", "ADDED"):    ("Persistence",         "LOW"),
    ("HKCU_RunOnce", "MODIFIED"): ("Persistence",         "LOW"),
    ("HKCU_RunOnce", "DELETED"):  ("Persistence",         "LOW"),

    # ── HKLM Run (system-wide persistence — all users affected) ─────────────
    ("HKLM_Run",     "ADDED"):    ("System Persistence",  "HIGH"),
    ("HKLM_Run",     "MODIFIED"): ("System Persistence",  "HIGH"),
    ("HKLM_Run",     "DELETED"):  ("System Persistence",  "MEDIUM"),
    ("HKLM_RunOnce", "ADDED"):    ("System Persistence",  "HIGH"),
    ("HKLM_RunOnce", "MODIFIED"): ("System Persistence",  "HIGH"),
    ("HKLM_RunOnce", "DELETED"):  ("System Persistence",  "MEDIUM"),

    # ── UAC (privilege escalation / security bypass) ─────────────────────────
    ("UAC_PolicySettings", "MODIFIED"): ("Security Bypass", "HIGH"),
    ("UAC_PolicySettings", "ADDED"):    ("Security Bypass", "HIGH"),
    ("UAC_PolicySettings", "DELETED"):  ("Security Bypass", "MEDIUM"),

    # ── Firewall (defense evasion — CRITICAL: no network protection) ─────────
    ("Firewall_StandardProfile", "MODIFIED"): ("Defense Evasion", "CRITICAL"),
    ("Firewall_StandardProfile", "ADDED"):    ("Defense Evasion", "CRITICAL"),
    ("Firewall_DomainProfile",   "MODIFIED"): ("Defense Evasion", "CRITICAL"),
    ("Firewall_DomainProfile",   "ADDED"):    ("Defense Evasion", "CRITICAL"),

    # ── Defender (defense evasion — CRITICAL: no AV protection) ─────────────
    ("Defender_Policy",              "MODIFIED"): ("Defense Evasion", "CRITICAL"),
    ("Defender_Policy",              "ADDED"):    ("Defense Evasion", "CRITICAL"),
    ("Defender_RealTimeProtection",  "MODIFIED"): ("Defense Evasion", "CRITICAL"),
    ("Defender_RealTimeProtection",  "ADDED"):    ("Defense Evasion", "CRITICAL"),

    # ── Winlogon (execution hijacking) ────────────────────────────────
    ("Winlogon_Shell",        "MODIFIED"): ("Execution Hijacking", "HIGH"),
    ("Winlogon_Shell",        "ADDED"):    ("Execution Hijacking", "HIGH"),
}

# Default threat for any change not explicitly listed above
DEFAULT_THREAT = ("Registry Change", "LOW")


def classify_threat(label, change_type):
    """
    Returns (threat_type, threat_risk) for a given registry key label + change type.
    Falls back to DEFAULT_THREAT if no specific classification exists.
    """
    return THREAT_CLASSIFICATION.get((label, change_type), DEFAULT_THREAT)


# ======================================================
# MONITORED REGISTRY KEYS
# ======================================================

MONITOR_KEYS = {

    # ── Autorun / Persistence Keys ──────────────────────────────────────────
    "HKCU_Run": (
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
    ),
    "HKCU_RunOnce": (
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
    "HKLM_Run": (
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
    ),
    "HKLM_RunOnce": (
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ),

    # ── Windows Defender / Antivirus Keys ───────────────────────────────────
    "Defender_Policy": (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows Defender",
    ),
    "Defender_RealTimeProtection": (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
    ),

    # ── Windows Firewall Keys ────────────────────────────────────────────────
    "Firewall_StandardProfile": (
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
    ),
    "Firewall_DomainProfile": (
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
    ),

    # ── UAC (User Account Control) Keys ─────────────────────────────────────
    "UAC_PolicySettings": (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    ),

    # ── Shell / Winlogon Key ─────────────────────────────────────────────────
    "Winlogon_Shell": (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ),
}


# ======================================================
# MALWARE PATTERNS
# ======================================================

MALWARE_PATTERNS = [
    {
        "key":   "Defender_Policy",
        "value": "DisableAntiSpyware",
        "data":  1,
        "alert": "Windows Defender AntiSpyware DISABLED via registry policy",
        "risk":  "HIGH",
    },
    {
        "key":   "Defender_RealTimeProtection",
        "value": "DisableRealtimeMonitoring",
        "data":  1,
        "alert": "Windows Defender Real-Time Monitoring DISABLED",
        "risk":  "HIGH",
    },
    {
        "key":   "Firewall_StandardProfile",
        "value": "EnableFirewall",
        "data":  0,
        "alert": "Standard Network Firewall has been DISABLED",
        "risk":  "HIGH",
    },
    {
        "key":   "Firewall_DomainProfile",
        "value": "EnableFirewall",
        "data":  0,
        "alert": "Domain Network Firewall has been DISABLED",
        "risk":  "HIGH",
    },
    {
        "key":   "UAC_PolicySettings",
        "value": "EnableLUA",
        "data":  0,
        "alert": "UAC (User Account Control) has been DISABLED — privilege escalation risk",
        "risk":  "HIGH",
    },
]


# ======================================================
# RISK SCORING TABLE
# ======================================================

CHANGE_POINTS = {
    ("HKLM_Run",              "ADDED"):    40,
    ("HKLM_Run",              "MODIFIED"): 40,
    ("HKLM_Run",              "DELETED"):  30,
    ("HKLM_RunOnce",          "ADDED"):    30,
    ("HKLM_RunOnce",          "MODIFIED"): 30,
    ("HKLM_RunOnce",          "DELETED"):  20,
    ("HKCU_Run",              "ADDED"):    20,
    ("HKCU_Run",              "MODIFIED"): 20,
    ("HKCU_Run",              "DELETED"):  15,
    ("HKCU_RunOnce",          "ADDED"):    10,
    ("HKCU_RunOnce",          "MODIFIED"): 10,
    ("HKCU_RunOnce",          "DELETED"):   8,
    ("Winlogon_Shell",        "MODIFIED"): 40,
    ("Winlogon_Shell",        "ADDED"):    40,
    ("IFEO_ExecutionOptions", "ADDED"):    35,
    ("IFEO_ExecutionOptions", "MODIFIED"): 35,
    ("Defender_Policy",       "MODIFIED"): 80,
    ("Defender_Policy",       "ADDED"):    80,
    ("Defender_RealTimeProtection", "MODIFIED"): 80,
    ("Defender_RealTimeProtection", "ADDED"):    80,
    ("UAC_PolicySettings",    "MODIFIED"): 60,
    ("UAC_PolicySettings",    "ADDED"):    60,
    ("Firewall_StandardProfile", "MODIFIED"): 80,
    ("Firewall_StandardProfile", "ADDED"):    80,
    ("Firewall_DomainProfile","MODIFIED"): 80,
    ("Firewall_DomainProfile","ADDED"):    80,
}

DEFAULT_CHANGE_POINTS = {
    "ADDED":    10,
    "MODIFIED":  8,
    "DELETED":   5,
}


# ======================================================
# LOGGING SETUP
# ======================================================

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

_console_handler = logging.StreamHandler()
_console_handler.setLevel(logging.INFO)
_console_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)
logging.getLogger().addHandler(_console_handler)


# ======================================================
# REGISTRY READ FUNCTIONS
# ======================================================

def read_registry_key(hive, path):
    """
    Opens a registry key (READ-ONLY) and returns all its values as a dict.
    { value_name: {"data": value_data, "type": reg_type} }
    """
    result = {}
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, value, reg_type = winreg.EnumValue(key, i)
                    result[name] = {"data": value, "type": reg_type}
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass
    except PermissionError:
        logging.warning(f"Permission denied reading: {path}")
    except OSError as exc:
        logging.warning(f"OS error reading {path}: {exc}")
    return result


def capture_snapshot():
    """
    Reads all monitored registry keys and returns the full current state.
    { key_label: {value_name: {data, type}, ...}, ... }
    """
    return {
        label: read_registry_key(hive, path)
        for label, (hive, path, *_) in MONITOR_KEYS.items()
    }


def hash_snapshot(snapshot):
    """SHA-256 hash of the entire snapshot for integrity verification."""
    raw = json.dumps(snapshot, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()


# ======================================================
# BASELINE FUNCTIONS
# ======================================================

def create_baseline():
    """
    --baseline mode: Captures a fresh baseline from the current registry state.

    Saves TWO files:
      registry_baseline.json        → Rolling baseline (updated after every scan)
      registry_baseline_clean.json  → Original clean copy (only written here, never again)

    The clean copy lets you --reset back to this original state at any time.
    """
    print("\n[MODE] Creating baseline snapshot...")
    print("       Capturing current registry state as trusted reference...")
    print()

    snapshot = capture_snapshot()

    payload = {
        "created_at": datetime.now().isoformat(),
        "hash":       hash_snapshot(snapshot),
        "tool":       "Windows Registry Change Monitoring System",
        "author":     "Sumit Dahiya (CDFE)",
        "data":       snapshot,
    }

    # Save rolling baseline
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)

    # Save clean backup (never overwritten except by --baseline)
    with open(CLEAN_BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)

    autoruns = get_autorun_entries(snapshot)
    print(f"  Key groups monitored : {len(MONITOR_KEYS)}")
    print(f"  Autorun entries found: {len(autoruns)}")

    if autoruns:
        print()
        print("  Current autorun entries (these are your KNOWN GOOD entries):")
        for e in autoruns:
            print(f"    [{e['risk']:<6}] [{e['location']:<16}]  {e['name']}  ->  {e['path']}")

    print()
    print(f"  Baseline hash (SHA-256): {payload['hash'][:40]}...")
    print()
    print("✅ Baseline saved successfully!")
    print(f"   Rolling baseline : {BASELINE_FILE}  (updated after each scan)")
    print(f"   Clean backup     : {CLEAN_BASELINE_FILE}  (use --reset to restore)")
    print()
    print("   Next steps:")
    print("   → python registrymonitor.py --scan      (one-time scan)")
    print("   → python registrymonitor.py --monitor   (continuous monitoring)")
    print("   → python registrymonitor.py --check     (quick integrity check)")
    print("   → python registrymonitor.py --reset     (restore original clean baseline)")

    logging.info(f"Baseline created — hash: {payload['hash'][:16]}... | Keys: {len(MONITOR_KEYS)}")


def load_baseline():
    """Loads the rolling baseline from disk. Returns None if not found."""
    if not Path(BASELINE_FILE).exists():
        return None
    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_baseline(baseline):
    """
    FIX #1 — Overwrites the rolling baseline file with the updated state.
    Called after every scan so the next scan compares against the latest
    known state, enabling correct MODIFIED detection.
    """
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2, default=str)


def reset_baseline():
    """
    FIX #2 — --reset mode: Copies the original clean baseline back over the
    rolling baseline, discarding all accumulated changes.

    Use this when you want to start fresh from the original trusted state.
    """
    print("\n[MODE] Resetting to original clean baseline...")

    if not Path(CLEAN_BASELINE_FILE).exists():
        print("❌  No clean baseline backup found.")
        print(f"    Please run: python registrymonitor.py --baseline  (first time setup)")
        return

    shutil.copy2(CLEAN_BASELINE_FILE, BASELINE_FILE)

    # Re-load to show info
    baseline = load_baseline()
    print(f"✅  Rolling baseline reset to original clean state.")
    print(f"   Original captured at : {baseline.get('created_at', 'N/A')}")
    print(f"   Hash (SHA-256)        : {baseline.get('hash', 'N/A')[:40]}...")
    print()
    print("   All accumulated rolling changes have been discarded.")
    print("   Next scan will compare against the original clean state.")
    logging.info("Rolling baseline reset to original clean backup.")


# ======================================================
# CHANGE DETECTION
# ======================================================

def compare_snapshots(old, new):
    """
    Compares two registry snapshots and returns all differences as a list.

    Detects three change types:
      ADDED    — value in 'new' but not in 'old'
      DELETED  — value in 'old' but not in 'new'
      MODIFIED — value in both but data differs  ← FIX #1 now works correctly
                                                    because 'old' is the rolling
                                                    baseline, not the stale original
    """
    changes = []
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for label in MONITOR_KEYS:
        old_vals = old.get(label, {})
        new_vals = new.get(label, {})

        # ADDED — new entries not present in the previous snapshot
        for name in new_vals:
            if name not in old_vals:
                threat_type, threat_risk = classify_threat(label, "ADDED")
                changes.append({
                    "timestamp":    ts,
                    "type":         "ADDED",
                    "label":        label,
                    "name":         name,
                    "old":          None,
                    "new":          new_vals[name],
                    "threat_type":  threat_type,
                    "threat_risk":  threat_risk,
                })

        # DELETED — entries removed since the previous snapshot
        for name in old_vals:
            if name not in new_vals:
                threat_type, threat_risk = classify_threat(label, "DELETED")
                changes.append({
                    "timestamp":    ts,
                    "type":         "DELETED",
                    "label":        label,
                    "name":         name,
                    "old":          old_vals[name],
                    "new":          None,
                    "threat_type":  threat_type,
                    "threat_risk":  threat_risk,
                })

        # MODIFIED — entries that exist in both but whose data has changed
        for name in new_vals:
            if name in old_vals and old_vals[name]["data"] != new_vals[name]["data"]:
                threat_type, threat_risk = classify_threat(label, "MODIFIED")
                changes.append({
                    "timestamp":    ts,
                    "type":         "MODIFIED",
                    "label":        label,
                    "name":         name,
                    "old":          old_vals[name],
                    "new":          new_vals[name],
                    "threat_type":  threat_type,
                    "threat_risk":  threat_risk,
                })

    return changes


def deduplicate_changes(all_changes, new_changes):
    """
    FIX #3 — Deduplicates the session-level change list.

    Problem this solves:
      Scan 1: PSDemoPersistence ADDED   (notepad.exe)
      Scan 2: PSDemoPersistence MODIFIED (calc.exe)
      Without dedup → report shows ADDED + MODIFIED (confusing)
      With dedup    → report shows ADDED with latest value (calc.exe)

    Rules:
      - If a key was previously ADDED this session and now shows MODIFIED,
        update the existing ADDED entry with the new value (not truly new anymore,
        just evolved — still report as ADDED since it didn't exist at session start).
      - If a key was previously ADDED/MODIFIED and now shows DELETED,
        remove it entirely (it came and went within the same session).
      - All other combinations are appended normally.

    Returns the updated all_changes list.
    """
    for new_c in new_changes:
        key = (new_c["label"], new_c["name"])

        # Find if this key already has an entry in the session change list
        existing_idx = next(
            (i for i, c in enumerate(all_changes)
             if c["label"] == new_c["label"] and c["name"] == new_c["name"]),
            None
        )

        if existing_idx is None:
            # First time seeing this key change — just append
            all_changes.append(new_c)

        else:
            existing = all_changes[existing_idx]

            if existing["type"] == "ADDED" and new_c["type"] == "MODIFIED":
                # Key was added this session and then modified — update the
                # ADDED entry's new value to the latest, keep type as ADDED
                all_changes[existing_idx]["new"] = new_c["new"]
                all_changes[existing_idx]["timestamp"] = new_c["timestamp"]

            elif existing["type"] in ("ADDED", "MODIFIED") and new_c["type"] == "DELETED":
                # Key appeared and then disappeared within the same session — remove it
                all_changes.pop(existing_idx)

            elif new_c["type"] == "MODIFIED":
                # Key was modified again — update to latest values
                all_changes[existing_idx]["new"] = new_c["new"]
                all_changes[existing_idx]["timestamp"] = new_c["timestamp"]

            else:
                # Any other case (e.g., DELETED then re-ADDED) — append fresh
                all_changes.append(new_c)

    return all_changes


# ======================================================
# MALWARE PATTERN DETECTION
# ======================================================

def check_malware_patterns(snapshot):
    """
    Checks the current snapshot against known malware indicator patterns.
    Returns a list of alert dicts: {timestamp, risk, alert}
    """
    alerts = []
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for pattern in MALWARE_PATTERNS:
        key_data = snapshot.get(pattern["key"], {})
        val = key_data.get(pattern["value"])
        if val is not None and val["data"] == pattern["data"]:
            alerts.append({
                "timestamp": ts,
                "risk":      pattern["risk"],
                "alert":     pattern["alert"],
            })

    # Special check: Shell replacement via Winlogon
    winlogon  = snapshot.get("Winlogon_Shell", {})
    shell_val = winlogon.get("Shell", {}).get("data", "")
    if shell_val and shell_val.strip().lower() not in ("explorer.exe", ""):
        alerts.append({
            "timestamp": ts,
            "risk":      "HIGH",
            "alert":     f"Shell replacement detected: '{shell_val}' (expected: explorer.exe)",
        })

    return alerts


# ======================================================
# AUTORUN ENTRIES
# ======================================================

def get_autorun_entries(snapshot):
    """
    Extracts all autorun entries from the snapshot.
    Risk: HKLM = HIGH (all users), HKCU = MEDIUM/LOW (current user only).
    """
    risk_map = {
        "HKLM_Run":     "HIGH",
        "HKLM_RunOnce": "HIGH",
        "HKCU_Run":     "MEDIUM",
        "HKCU_RunOnce": "LOW",
    }
    entries = []
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for label in ["HKCU_Run", "HKCU_RunOnce", "HKLM_Run", "HKLM_RunOnce"]:
        for name, info in snapshot.get(label, {}).items():
            entries.append({
                "timestamp": ts,
                "risk":      risk_map.get(label, "LOW"),
                "location":  label,
                "name":      name,
                "path":      info["data"],
            })
    return entries


# ======================================================
# SUSPICIOUS PATH SCORING
# ======================================================

def suspicious_path_scoring(snapshot):
    """
    Awards extra risk points for autorun entries pointing to suspicious paths
    (AppData, Temp, Public, etc.) commonly used by malware.
    """
    points = 0
    for label in ["HKCU_Run", "HKCU_RunOnce", "HKLM_Run", "HKLM_RunOnce"]:
        for name, info in snapshot.get(label, {}).items():
            path = str(info.get("data", ""))
            for bad_location in SUSPICIOUS_LOCATIONS:
                if bad_location.lower() in path.lower():
                    points += 25
                    logging.warning(
                        f"Suspicious autorun path [{label}] '{name}' -> {path}"
                    )
                    break
    return points


# ======================================================
# RISK SCORING ENGINE
# ======================================================

def calculate_risk(changes, snapshot):
    """
    Calculates overall risk score:
      🟢 LOW      = 0–29 pts
      🟡 MEDIUM   = 30–59 pts
      🔴 HIGH     = 60–79 pts
      🔴 CRITICAL = 80+ pts

    Also consults threat_risk from THREAT_CLASSIFICATION so a CRITICAL-classified
    change (e.g. Defender ADDED) is never under-scored by the points table alone.
    """
    score     = 0
    breakdown = []
    severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    for c in changes:
        pts = CHANGE_POINTS.get(
            (c["label"], c["type"]),
            DEFAULT_CHANGE_POINTS.get(c["type"], 5)
        )

        # Enforce minimum points based on threat classification risk level
        # so the summary can never contradict what the threat classifier says
        threat_risk = c.get("threat_risk", "LOW")
        if threat_risk == "CRITICAL":
            pts = max(pts, 80)
        elif threat_risk == "HIGH":
            pts = max(pts, 40)
        elif threat_risk == "MEDIUM":
            pts = max(pts, 20)

        score += pts
        breakdown.append({
            "reason":   f"{c['type']} '{c['name']}' in {c['label']}",
            "points":   pts,
            "category": _change_category(c["label"]),
        })

    sus_pts = suspicious_path_scoring(snapshot)
    if sus_pts:
        score += sus_pts
        breakdown.append({
            "reason":   "Autorun entry in suspicious path (AppData / Temp / Public)",
            "points":   sus_pts,
            "category": "Suspicious Path",
        })

    if score >= 80:
        level, label = "CRITICAL", "🔴 CRITICAL RISK"
    elif score >= 60:
        level, label = "HIGH",     "🔴 HIGH RISK"
    elif score >= 30:
        level, label = "MEDIUM",   "🟡 MEDIUM RISK"
    else:
        level, label = "LOW",      "🟢 LOW RISK"

    return {
        "total_score": score,
        "level":       level,
        "label":       label,
        "breakdown":   breakdown,
    }


def _change_category(label):
    """Human-readable category for a registry key label."""
    if "Run" in label:
        return "Autorun / Persistence"
    if label in ("Defender_Policy", "Defender_RealTimeProtection"):
        return "Security Tool Tampering"
    if "Firewall" in label:
        return "Firewall Tampering"
    if label == "UAC_PolicySettings":
        return "Privilege Escalation"
    if label in ("Winlogon_Shell", "IFEO_ExecutionOptions"):
        return "Shell / Execution Hijacking"
    return "Registry Change"


# ======================================================
# CONSOLE LOGGING OF LIVE CHANGES
# ======================================================

def log_changes(changes, alerts):
    """
    Logs each detected change and alert to both the log file and console.
    ADDED/MODIFIED = WARNING level | DELETED = INFO | Alerts = CRITICAL
    """
    if not changes and not alerts:
        logging.info("✔ No changes detected in this scan.")
        return

    for c in changes:
        hive, path, *_ = MONITOR_KEYS[c["label"]]
        hive_str = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"

        pts  = CHANGE_POINTS.get(
            (c["label"], c["type"]),
            DEFAULT_CHANGE_POINTS.get(c["type"], 5)
        )
        risk = "HIGH" if pts >= 35 else ("MEDIUM" if pts >= 20 else "LOW")

        c["_risk"]   = risk
        c["_points"] = pts

        # Use threat classification risk if it's more severe than score-based risk
        threat_risk = c.get("threat_risk", "LOW")
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        display_risk = (
            threat_risk
            if severity_order.index(threat_risk) > severity_order.index(risk)
            else risk
        )
        c["_risk"] = display_risk

        threat_type = c.get("threat_type", "Registry Change")

        line = (
            f"{c['type']} [{display_risk}] [{threat_type}]: "
            f"{hive_str}\\{path} -> {c['name']}"
        )

        if c["type"] in ("ADDED", "MODIFIED"):
            logging.warning(line)
        else:
            logging.info(line)

    for a in alerts:
        logging.critical(f"MALWARE ALERT [{a['risk']}]: {a['alert']}")


# ======================================================
# REPORT GENERATOR
# ======================================================

def generate_report(changes, alerts, autoruns, baseline_info, risk):
    """
    Generates a complete forensic report:
      1. Header
      2. Risk Assessment
      3. Malware Alerts
      4. Registry Change Event Log
      5. Autorun Entries
      6. Summary
    """
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep  = "=" * 75
    thin = "-" * 75
    lines = []

    # ── HEADER ──────────────────────────────────────────────────────────────
    lines.append(sep)
    lines.append("       WINDOWS REGISTRY CHANGE MONITORING SYSTEM — FORENSIC REPORT")
    lines.append(sep)
    lines.append(f"  Report Generated   : {now}")
    lines.append(f"  Baseline Captured  : {baseline_info.get('created_at', 'N/A')}")
    lines.append(f"  Baseline Hash      : {baseline_info.get('hash', 'N/A')[:40]}...")
    lines.append(f"  Author             : {baseline_info.get('author', 'Sumit Dahiya (CDFE)')}")
    lines.append(f"  Total Changes      : {len(changes)}")
    lines.append(f"  Malware Alerts     : {len(alerts)}")
    lines.append(f"  Autorun Entries    : {len(autoruns)}")
    lines.append(f"  Keys Monitored     : {len(MONITOR_KEYS)}")
    lines.append(sep)
    lines.append("")

    # ── RISK ASSESSMENT ──────────────────────────────────────────────────────
    bar_filled = min(int(risk["total_score"] / 100 * 45), 45)
    bar = "█" * bar_filled + "░" * (45 - bar_filled)

    lines.append("1. RISK ASSESSMENT")
    lines.append(thin)
    lines.append(f"   Overall Risk Level : {risk['label']}")
    lines.append(f"   Risk Score         : {risk['total_score']}  "
                 f"[ LOW: 0–29 | MEDIUM: 30–59 | HIGH: 60–79 | CRITICAL: 80+ ]")
    lines.append(f"   Score Meter        : [{bar}]")
    lines.append("")
    lines.append("   Risk Factor Breakdown:")

    if risk["breakdown"]:
        categories = {}
        for item in risk["breakdown"]:
            categories.setdefault(item["category"], []).append(item)
        for cat, items in categories.items():
            cat_pts = sum(i["points"] for i in items)
            lines.append(f"     ▸ {cat}  (+{cat_pts} pts total)")
            for item in items:
                lines.append(f"          +{item['points']:>3} pts  —  {item['reason']}")
    else:
        lines.append("     ✔  No risk factors detected — system appears clean.")
    lines.append("")

    # ── MALWARE PATTERN ALERTS ───────────────────────────────────────────────
    lines.append("2. MALWARE-PATTERN ALERTS")
    lines.append(thin)
    if alerts:
        for a in alerts:
            lines.append(
                f"   [{a['timestamp']}] ⚠ MALWARE ALERT [{a['risk']}]: {a['alert']}"
            )
    else:
        lines.append("   ✔  No malware-pattern matches detected.")
    lines.append("")

    # ── REGISTRY CHANGE EVENT LOG ────────────────────────────────────────────
    lines.append("3. REGISTRY CHANGE EVENT LOG")
    lines.append(thin)
    lines.append(
        f"   {'TIMESTAMP':<22} {'TYPE':<10} {'RISK':<10} {'THREAT TYPE':<22} REGISTRY PATH  ->  VALUE"
    )
    lines.append(f"   {'-'*22} {'-'*10} {'-'*10} {'-'*22} {'-'*42}")

    if changes:
        for c in changes:
            hive, subkey, *_ = MONITOR_KEYS[c["label"]]
            hive_str     = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
            entry_risk   = c.get("_risk", "LOW")
            threat_type  = c.get("threat_type", "Registry Change")

            lines.append(
                f"   [{c['timestamp']}] {c['type']:<10} [{entry_risk:<8}]  "
                f"{threat_type:<22} {hive_str}\\{subkey} -> {c['name']}"
            )

            old_data = c["old"]["data"] if c["old"] else None
            new_data = c["new"]["data"] if c["new"] else None

            if old_data is not None and new_data is not None:
                lines.append(f"     {'':22}  Old Value : {old_data!r}")
                lines.append(f"     {'':22}  New Value : {new_data!r}")
            elif old_data is None:
                lines.append(f"     {'':22}  New Value : {new_data!r}")
            else:
                lines.append(f"     {'':22}  Removed   : {old_data!r}")
            lines.append("")
    else:
        lines.append("   ✔  No registry changes detected since baseline.")
    lines.append("")

    # ── THREAT CLASSIFICATION SUMMARY ───────────────────────────────────────
    lines.append("4. THREAT CLASSIFICATION SUMMARY")
    lines.append(thin)
    lines.append(
        f"   {'REGISTRY CHANGE':<40} {'THREAT TYPE':<22} {'RISK':<10}"
    )
    lines.append(f"   {'-'*40} {'-'*22} {'-'*10}")

    if changes:
        for c in changes:
            hive, subkey, *_ = MONITOR_KEYS[c["label"]]
            hive_str    = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
            threat_type = c.get("threat_type", "Registry Change")
            threat_risk = c.get("threat_risk", "LOW")
            change_desc = f"{c['type']} {hive_str}\\...\\{c['label'].split('_')[-1]} -> {c['name']}"

            lines.append(
                f"   {change_desc:<40} {threat_type:<22} [{threat_risk}]"
            )
    else:
        lines.append("   ✔  No threats classified — no changes detected.")
    lines.append("")

    # ── AUTORUN ENTRIES ──────────────────────────────────────────────────────
    lines.append("5. AUTORUN ENTRIES DETECTED")
    lines.append(thin)
    if autoruns:
        lines.append(
            f"   {'TIMESTAMP':<22} {'RISK':<8} {'LOCATION':<22} {'NAME':<26} EXECUTABLE PATH"
        )
        lines.append(f"   {'-'*22} {'-'*8} {'-'*22} {'-'*26} {'-'*35}")
        for e in autoruns:
            lines.append(
                f"   [{e['timestamp']}] [{e['risk']:<6}]  "
                f"{e['location']:<22} {e['name']:<26} {e['path']}"
            )
    else:
        lines.append("   No autorun entries found.")
    lines.append("")

    # ── SUMMARY ─────────────────────────────────────────────────────────────
    lines.append("6. SUMMARY")
    lines.append(thin)
    lines.append(f"   Report Timestamp   : {now}")
    lines.append(f"   Risk Level         : {risk['label']}")
    lines.append(f"   Risk Score         : {risk['total_score']}")
    lines.append(f"   Changes Detected   : {len(changes)}")
    lines.append(f"     ↳ ADDED          : {sum(1 for c in changes if c['type'] == 'ADDED')}")
    lines.append(f"     ↳ MODIFIED       : {sum(1 for c in changes if c['type'] == 'MODIFIED')}")
    lines.append(f"     ↳ DELETED        : {sum(1 for c in changes if c['type'] == 'DELETED')}")
    lines.append(f"   Malware Alerts     : {len(alerts)}")
    lines.append(f"   Autorun Entries    : {len(autoruns)}")
    lines.append("")
    lines.append("   FORENSIC NOTE: This tool operates in READ-ONLY mode.")
    lines.append("   The registry is never modified by this tool.")
    lines.append("   All findings should be correlated with event logs and process activity.")
    lines.append(f"   Rolling Baseline   : {BASELINE_FILE}")
    lines.append(f"   Clean Backup       : {CLEAN_BASELINE_FILE}")
    lines.append(f"   Log File           : {LOG_FILE}")
    lines.append(f"   Report File        : {REPORT_FILE}")
    lines.append(sep)

    report_text = "\n".join(lines)

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(report_text)

    print("\n" + report_text + "\n")
    logging.info(f"Forensic report saved to '{REPORT_FILE}'")


# ======================================================
# RISK BANNER
# ======================================================

def print_risk_banner(risk):
    """Prints a prominent risk summary block to the console."""
    sep = "=" * 65
    bar_filled = min(int(risk["total_score"] / 100 * 40), 40)
    bar = "█" * bar_filled + "░" * (40 - bar_filled)

    print("\n" + sep)
    print(f"  RISK ASSESSMENT:  {risk['label']}")
    print(f"  Score : {risk['total_score']:>4}   [{bar}]")
    print(f"  LOW: 0-29  |  MEDIUM: 30-59  |  HIGH: 60-79  |  CRITICAL: 80+")
    print(sep)

    if risk["breakdown"]:
        print("  Factors contributing to risk score:")
        for item in risk["breakdown"]:
            print(f"    +{item['points']:>3} pts  [{item['category']}]  {item['reason']}")
    else:
        print("  ✔  No risk factors — system appears clean.")

    print(sep + "\n")
    logging.info(f"Risk Score: {risk['total_score']} | Level: {risk['level']}")


# ======================================================
# MONITORING MODES
# ======================================================

def monitor(single_scan=False):
    """
    Core monitoring function used by --scan and --monitor modes.

    Key changes vs v1:
    ─────────────────
    FIX #1 (MODIFIED detection):
      After each scan, baseline["data"] is updated to the current snapshot
      and written back to disk via save_baseline(). This means the next scan
      compares against the most recently seen state — so a value change that
      was previously seen as ADDED will correctly show as MODIFIED next time.

    FIX #3 (Deduplication):
      all_changes is built through deduplicate_changes() which merges
      ADDED → MODIFIED into a single ADDED entry (with updated value),
      and removes ADDED → DELETED pairs that cancelled out within the session.
    """
    baseline = load_baseline()
    if not baseline:
        print("❌  No baseline found.")
        print(f"    Please run: python registrymonitor.py --baseline")
        return

    print(f"\n[MODE] {'Single scan' if single_scan else 'Continuous monitoring'}...")
    print(f"  Baseline captured : {baseline['created_at']}")
    print(f"  Keys monitored    : {len(MONITOR_KEYS)}")

    if not single_scan:
        print(f"  Scan interval     : {POLL_INTERVAL_SECONDS} seconds")
        print(f"  Press Ctrl+C to stop monitoring and generate final report.")
    print()

    all_changes = []
    all_alerts  = []
    scan_count  = 0

    try:
        while True:
            scan_count += 1
            if not single_scan:
                print(f"[SCAN #{scan_count}] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            # Take fresh snapshot and compare against the ROLLING baseline
            current = capture_snapshot()
            changes = compare_snapshots(baseline["data"], current)
            alerts  = check_malware_patterns(current)

            # Log findings to file and console
            log_changes(changes, alerts)

            # ── FIX #1: Update rolling baseline so next scan sees MODIFIED ──
            baseline["data"] = current
            baseline["hash"] = hash_snapshot(current)
            save_baseline(baseline)

            # ── FIX #3: Deduplicate session-level change list ────────────────
            all_changes = deduplicate_changes(all_changes, changes)

            # Accumulate unique alerts
            for a in alerts:
                if a not in all_alerts:
                    all_alerts.append(a)

            if single_scan:
                break

            time.sleep(POLL_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\n  ⚠  Monitoring stopped by user.")
        print(f"  Total scans completed: {scan_count}")

    current_final = capture_snapshot()
    autoruns      = get_autorun_entries(current_final)
    risk          = calculate_risk(all_changes, current_final)

    print_risk_banner(risk)
    generate_report(all_changes, all_alerts, autoruns, baseline, risk)


def integrity_check():
    """
    --check mode: SHA-256 hash-based integrity check vs the rolling baseline.
    If hashes differ, automatically runs a full scan to identify what changed.
    """
    baseline = load_baseline()
    if not baseline:
        print("❌  No baseline found.")
        print(f"    Please run: python registrymonitor.py --baseline")
        return

    print("\n[MODE] Registry Integrity Check...")
    print(f"  Comparing current state against baseline from: {baseline['created_at']}")
    print()

    current      = capture_snapshot()
    current_hash = hash_snapshot(current)
    saved_hash   = baseline.get("hash", "")

    print(f"  Baseline hash (SHA-256) : {saved_hash[:40]}...")
    print(f"  Current hash  (SHA-256) : {current_hash[:40]}...")
    print()

    if current_hash == saved_hash:
        print("  ✅  INTEGRITY CHECK PASSED")
        print("      Registry matches baseline exactly. No changes detected.")
        logging.info("Integrity check PASSED.")
        risk = calculate_risk([], current)
        print_risk_banner(risk)
    else:
        print("  ❌  INTEGRITY CHECK FAILED")
        print("      Registry has changed since baseline was captured!")
        print("      Running detailed scan to identify what changed...")
        logging.warning("Integrity check FAILED — running detailed scan...")
        monitor(single_scan=True)


# ======================================================
# ENTRY POINT
# ======================================================

if __name__ == "__main__":
    print("=" * 65)
    print("  Windows Registry Change Monitoring System")
    print("  Author: Sumit Dahiya (CDFE) | Unified Mentor Internship")
    print("=" * 65)

    mode = sys.argv[1] if len(sys.argv) > 1 else "--help"

    if mode == "--baseline":
        create_baseline()

    elif mode == "--monitor":
        monitor(single_scan=False)

    elif mode == "--scan":
        monitor(single_scan=True)

    elif mode == "--check":
        integrity_check()

    elif mode == "--reset":
        # FIX #2: Restore original clean baseline, discarding rolling changes
        reset_baseline()

    else:
        print("""
Usage:
  python registrymonitor.py --baseline   Capture baseline (run FIRST on clean system)
  python registrymonitor.py --monitor    Continuous monitoring (Ctrl+C to stop + report)
  python registrymonitor.py --scan       One-shot scan and report
  python registrymonitor.py --check      Quick integrity hash check vs baseline
  python registrymonitor.py --reset      Restore original clean baseline (discard rolling changes)

Typical Workflow:
  1. python registrymonitor.py --baseline   (once, on a clean system)
  2. python registrymonitor.py --monitor    (ongoing monitoring)
  3. python registrymonitor.py --check      (anytime to verify integrity)
  4. python registrymonitor.py --reset      (if you want to start fresh)

Output Files:
  registry_baseline.json        Rolling baseline (updated after every scan)
  registry_baseline_clean.json  Original clean backup (only written by --baseline)
  registry_changes.log          Running log of all detected changes
  registry_report.txt           Final forensic report
""")