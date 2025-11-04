#!/usr/bin/env python3
"""
attack_to_capec_list.py

Given a MITRE ATT&CK ID (e.g. T1595 or T1574.010), this script:
  1. Detects which ATT&CK domain (Enterprise, Mobile, or ICS) contains it.
  2. Extracts CAPEC IDs from that ATT&CK object's external_references.
  3. Falls back to searching the CAPEC bundle if needed.
  4. Returns ONLY a list of CAPEC IDs (no extra output).

Requires: requests
"""

import re
import requests
import json

# --- Constants ---
BUNDLES = {
    "enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json",
    "mobile":     "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/mobile-attack/mobile-attack.json",
    "ics":        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/ics-attack/ics-attack.json",
}
CAPEC_BUNDLE_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
ATTACK_ID_RE = re.compile(r"^T\d{3,6}(\.\d{3})?$", re.IGNORECASE)
CAPEC_RE = re.compile(r"(CAPEC[- ]?\d+)", re.IGNORECASE)


def fetch_json(url: str):
    """Fetch JSON data from a URL."""
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.json()


def find_attack_object(bundle, attack_id):
    """Find the attack-pattern object by ATT&CK ID in a STIX bundle."""
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").upper() == attack_id.upper():
                return obj
    return None


def extract_capecs_from_attack_object(obj):
    """Extract CAPEC IDs from an ATT&CK STIX object."""
    capecs = set()
    for ref in obj.get("external_references", []):
        if "capec" in str(ref.get("source_name", "")).lower():
            ext_id = ref.get("external_id", "")
            match = CAPEC_RE.search(ext_id)
            if match:
                capecs.add(match.group(1).upper().replace(" ", "-"))
    return sorted(capecs)


def search_capec_bundle_for_attack(capec_bundle, attack_id):
    """Search CAPEC bundle for references to the ATT&CK ID (fallback)."""
    atk_upper = attack_id.upper()
    capecs = set()
    for obj in capec_bundle.get("objects", []):
        data_str = json.dumps(obj).upper()
        if atk_upper not in data_str:
            continue
        for ref in obj.get("external_references", []):
            ext_id = ref.get("external_id", "")
            match = CAPEC_RE.search(ext_id)
            if match:
                capecs.add(match.group(1).upper().replace(" ", "-"))
    return sorted(capecs)


def get_capec_ids(attack_id: str):
    """Return a list of CAPEC IDs related to the ATT&CK ID."""
    if not ATTACK_ID_RE.match(attack_id):
        raise ValueError("Invalid ATT&CK ID format. Example: T1595 or T1574.010")

    attack_id = attack_id.upper()
    capec_ids = []

    # Step 1: Detect which bundle contains this ATT&CK ID
    for domain, url in BUNDLES.items():
        try:
            bundle = fetch_json(url)
        except Exception:
            continue
        attack_obj = find_attack_object(bundle, attack_id)
        if attack_obj:
            capec_ids = extract_capecs_from_attack_object(attack_obj)
            break

    # Step 2: Fallback — search CAPEC bundle if none found
    if not capec_ids:
        try:
            capec_bundle = fetch_json(CAPEC_BUNDLE_URL)
            capec_ids = search_capec_bundle_for_attack(capec_bundle, attack_id)
        except Exception:
            pass

    return capec_ids
