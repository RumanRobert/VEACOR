#!/usr/bin/env python3
import re
import json
import sys
import time
from typing import Dict, Any
import os
import logging
import argparse
from veacor.Retrieves.NLP_relationship_finder import set_linking_config
from pathlib import Path
EXPANSION_RULES = {
    "CVE": {
        "CVE":   ["CWE"],
        "CWE":   ["CAPEC"],
        "CAPEC": ["ATTACK"],
        "ATTACK":["DEFEND"],
    },

    "CWE": {
        "CWE":   ["CVE", "CAPEC"],
        "CAPEC": ["ATTACK"],
        "ATTACK":["DEFEND"],
    },

    "CAPEC": {
        "CAPEC": ["CWE", "ATTACK"],
        "CWE":   ["CVE"],        # ❌ NO CWE→CAPEC!
        "ATTACK":["DEFEND"],
    },

    "ATTACK": {
        "ATTACK":["DEFEND", "CAPEC"],
        "CAPEC": ["CWE"],
        "CWE":   ["CVE"],
    },

    "DEFEND": {
        "DEFEND":[],
        "ATTACK":["CAPEC"],
        "CAPEC": ["CWE"],
        "CWE":   ["CVE"],
    }
}

def lazy_imports():
    global fetch_cve_data, fetch_cwe_data, fetch_capec_data, fetch_cpe_data
    global fetch_attack_data, fetch_defend_data
    global link_nodes
    start = time.time()
    print("Importing NLP...")
    from veacor.Retrieves.NLP_relationship_finder import link_nodes
    print("NLP import:", time.time() - start)
    start = time.time()
    print("Importing CPE...")
    from veacor.Retrieves.CPE_retrieve import fetch_cpe_data
    print("Importing CVE...")
    from veacor.Retrieves.CVE_retrieve import fetch_cve_data
    print("CVE import:", time.time() - start)
    start = time.time()
    print("Importing CWE...")
    from veacor.Retrieves.CWE_retrieve import fetch_cwe_data
    print("CWE import:", time.time() - start)
    start = time.time()
    print("Importing CAPEC...")
    from veacor.Retrieves.CAPEC_retrieve import fetch_capec_data
    print("CAPEC import:", time.time() - start)
    start = time.time()
    print("Importing ATTACK/DEFEND...")
    from veacor.Retrieves.ATTACKDEFEND_retrieve import fetch_attack_data, fetch_defend_data
    print("ATTACK/DEFEND import:", time.time() - start)

#DEFINITIONS
# --- LOGGING CONFIGURATION ---
LOG_DIR = os.path.expanduser("~/.cache/cyberdata/logs")
os.makedirs(LOG_DIR, exist_ok=True)

log_file = os.path.join(LOG_DIR, "roadmap_builder.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_file, mode='a', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("roadmap")

# === CVE LIMIT CONFIGURATION ===
FETCH_LIMIT = 5  # default value; can be changed by CLI flag

def is_keyword_or_text(user_input: str) -> str:
    """
    Determines whether input is a keyword, text, or valid ID.
    Returns one of: 'keyword', 'text', or 'id'.
    """
    detected = detect_type(user_input)
    if detected != "UNKNOWN":
        return "id"

    if len(user_input.strip().split()) > 1:
        return "text"
    return "keyword"

def ensure_list(x):
    """
    Safely converts any input into a flat list.
    Supports strings, sets, dicts, and lists.
    """
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, set):
        return list(x)
    if isinstance(x, dict):
        return [x]
    return [x]


def strip_nlp_suffix(x: str) -> str:
    if not isinstance(x, str):
        return x
    return re.sub(r"\s*-\s*NLP\s+Link\s*$", "", x, flags=re.I).strip()

def extract_id_from_item(item: dict) -> tuple[str | None, str | None]:
    """
    Given a link_nodes() 'item', extract (id, type).
    """
    if not isinstance(item, dict):
        return None, None

    if item.get("CWE_ID"):
        return strip_nlp_suffix(item["CWE_ID"]), "CWE"
    if item.get("CAPEC_ID"):
        return strip_nlp_suffix(item["CAPEC_ID"]), "CAPEC"
    if item.get("ATTACK_ID"):
        return strip_nlp_suffix(item["ATTACK_ID"]), "ATTACK"
    if item.get("DEFEND_ID"):
        return strip_nlp_suffix(item["DEFEND_ID"]), "DEFEND"
    if item.get("CVE_ID"):
        return strip_nlp_suffix(item["CVE_ID"]), "CVE"

    return None, None

def resolve_text_to_best_id(
    text: str,
    top_k_each: int = 5,
    limit: int = 600,
    forced_target_type: str | None = None
):
    """
    Resolve free text -> best matching entity ID using NLP similarity.
    Returns:
      (best_id, best_type, best_score, debug_results)
    """
    if forced_target_type:
        target_types = [forced_target_type.strip().upper()]
    else:
        target_types = ["CWE", "CAPEC", "ATTACK", "DEFEND"]

    all_hits = []
    debug = {}

    for tgt in target_types:
        try:
            ranked = link_nodes(
                source_description=text,
                source_type="TEXT",
                target_type=tgt,
                top_k=top_k_each,
                limit=limit
            )
            debug[tgt] = ranked

            for r in ranked:
                item = r.get("item", {})
                score = float(r.get("score", 0.0))
                rid, rtype = extract_id_from_item(item)
                if rid and rtype:
                    all_hits.append((score, rid, rtype, r))
        except Exception as e:
            logger.warning(f"[NLP] resolve_text_to_best_id failed for target={tgt}: {e}")
            debug[tgt] = []

    if not all_hits:
        return None, None, 0.0, debug

    all_hits.sort(key=lambda x: x[0], reverse=True)
    best_score, best_id, best_type, best_raw = all_hits[0]
    return best_id, best_type, best_score, debug
# === Type Detection ===
def detect_type(identifier: str) -> str:
    s = identifier.strip().upper()

    if re.match(r"^CVE-\d{4}-\d+$", s):
        return "CVE"
    if re.match(r"^CWE-\d+$", s):
        return "CWE"
    if re.match(r"^CAPEC-\d+$", s):
        return "CAPEC"
    if re.match(r"^T\d{3,6}(?:\.\d+)?$", s):
        return "ATTACK"
    if s.startswith("D3-"):
        return "DEFEND"
    if s.startswith("cpe"):
        return "CPE"
    # handle weird prefixes like "NVD-CWE-79"
    if "CWE-" in s:
        return "CWE"
    if "CAPEC-" in s:
        return "CAPEC"

    return "UNKNOWN"

# === Global visited registry ===
visited = {"CPE": set(), "CVE": set(), "CWE": set(), "CAPEC": set(), "ATTACK": set(), "DEFEND": set()}
# === Global cache to avoid duplicate fetches ===
cache = {"CPE": {}, "CVE": {}, "CWE": {}, "CAPEC": {}, "ATTACK": {}, "DEFEND": {}}


def handle_cve_input(cve_id: str) -> Dict[str, Any]:
    for key in visited:
        visited[key].clear()
    result = {
        "Query": cve_id,
        "Detected_Type": "CVE",
        "Nodes": {"CVE": [], "CWE": [], "CAPEC": [], "ATTACK": [], "DEFEND": []},
        "Notes": []
    }
    logger.info(f"\n[+] Building roadmap for {cve_id} (ATTACK mode)...")
    data = cache["CVE"].get(cve_id) or fetch_cve_data(cve_id)
    cache["CVE"][cve_id] = data
    result["Nodes"]["CVE"].append(data)
    visited["CVE"].add(cve_id)

    # 1️⃣ CVE → Related CWEs
    for cwe in ensure_list(data.get("Related_CWEs")):
        if cwe not in visited["CWE"]:
            cwe_data = cache["CWE"].get(cwe) or fetch_cwe_data(cwe)
            cache["CWE"][cwe] = cwe_data
            result["Nodes"]["CWE"].append(cwe_data)
            visited["CWE"].add(cwe)

        # 2️⃣ CWE → Related CAPEC
        for capec in ensure_list(cwe_data.get("Related_CAPEC")):
            if capec not in visited["CAPEC"]:
                capec_data = cache["CAPEC"].get(capec) or fetch_capec_data(capec)
                cache["CAPEC"][capec] = capec_data
                result["Nodes"]["CAPEC"].append(capec_data)
                visited["CAPEC"].add(capec)

                # 3️⃣ CAPEC → ATTACK
                for attack in ensure_list(capec_data.get("Related_MITRE_ATT&CK")):
                    if attack not in visited["ATTACK"]:
                        attack_data = cache["ATTACK"].get(attack) or fetch_attack_data(attack)
                        cache["ATTACK"][attack] = attack_data
                        result["Nodes"]["ATTACK"].append(attack_data)
                        visited["ATTACK"].add(attack)

                        # 4️⃣ ATTACK → DEFEND
                        for defend in ensure_list(attack_data.get("DEFEND")):
                            if defend not in visited["DEFEND"]:
                                defend_data = cache["DEFEND"].get(defend) or fetch_defend_data(defend)
                                cache["DEFEND"][defend] = defend_data
                                result["Nodes"]["DEFEND"].append(defend_data)
                                visited["DEFEND"].add(defend)

    return result

def handle_cwe_input(cwe_id: str) -> Dict[str, Any]:
    for key in visited:
        visited[key].clear()
    result = {
        "Query": cwe_id,
        "Detected_Type": "CWE",
        "Nodes": {"CVE": [], "CWE": [], "CAPEC": [], "ATTACK": [], "DEFEND": []},
        "Notes": []
    }

    logger.info(f"\n[+] Building roadmap for {cwe_id} (ATTACK mode)...")

    # 1️⃣ Fetch CWE node itself
    cwe_data = cache["CWE"].get(cwe_id) or fetch_cwe_data(cwe_id)
    cache["CWE"][cwe_id] = cwe_data
    result["Nodes"]["CWE"].append(cwe_data)
    visited["CWE"].add(cwe_id)

    # --- NEW: Check for prohibited mapping ---
    vm_note = cwe_data.get("Vulnerability_Mapping") or ""
    if isinstance(vm_note, str) and "PROHIBITED" in vm_note.upper():
        result["Notes"].append(
            "This CWE ID must not be used to map to real-world vulnerabilities"
        )
    # 3️⃣ Fetch CWE
    for cve in ensure_list(cwe_data.get("Related_CVEs")):
        if cve not in visited["CVE"]:
            cve_data = cache["CVE"].get(cve) or fetch_cve_data(cve)
            cache["CVE"][cve] = cve_data
            result["Nodes"]["CVE"].append(cve_data)
            visited["CVE"].add(cve)

    for capec in ensure_list(cwe_data.get("Related_CAPEC")):
        if capec not in visited["CAPEC"]:
            capec_data = cache["CAPEC"].get(capec) or fetch_capec_data(capec)
            cache["CAPEC"][capec] = capec_data
            result["Nodes"]["CAPEC"].append(capec_data)
            visited["CAPEC"].add(capec)
    # Get DEFEND data for ATTACK related to this CAPEC
            for attack in ensure_list(capec_data.get("Related_MITRE_ATT&CK")):
                if attack not in visited["ATTACK"]:
                    attack_data = cache["ATTACK"].get(attack) or fetch_attack_data(attack)
                    cache["ATTACK"][attack] = attack_data
                    result["Nodes"]["ATTACK"].append(attack_data)
                    visited["ATTACK"].add(attack)
                    for defend in ensure_list(attack_data.get("DEFEND")):
                        if defend not in visited["DEFEND"]:
                            defend_data = cache["DEFEND"].get(defend) or fetch_defend_data(defend)
                            cache["DEFEND"][defend] = defend_data
                            result["Nodes"]["DEFEND"].append(defend_data)
                            visited["DEFEND"].add(defend)

    return result

def handle_capec_input(capec_id: str) -> Dict[str, Any]:
    for key in visited:
        visited[key].clear()
    result = {
        "Query": capec_id,
        "Detected_Type": "CAPEC",
        "Nodes": {"CVE": [], "CWE": [], "CAPEC": [], "ATTACK": [], "DEFEND": []},
        "Notes": []
    }

    logger.info(f"\n[+] Building roadmap for {capec_id} (ATTACK mode)...")

    # 1️⃣ Fetch CAPEC node itself
    capec_data = cache["CAPEC"].get(capec_id) or fetch_capec_data(capec_id)
    cache["CAPEC"][capec_id] = capec_data
    result["Nodes"]["CAPEC"].append(capec_data)
    visited["CAPEC"].add(capec_id)

    # 2️⃣ Add all its CWE links
    for cwe in ensure_list(capec_data.get("Related_CWEs")):
        if cwe not in visited["CWE"]:
            cwe_data = cache["CWE"].get(cwe) or fetch_cwe_data(cwe)
            cache["CWE"][cwe] = cwe_data
            result["Nodes"]["CWE"].append(cwe_data)
            visited["CWE"].add(cwe)
        # 3️⃣ Fetch data related to CAPEC-CWEs
            for cve in ensure_list(cwe_data.get("Related_CVEs")):
                if cve not in visited["CVE"]:
                    cve_data = cache["CVE"].get(cve) or fetch_cve_data(cve)
                    cache["CVE"][cve] = cve_data
                    result["Nodes"]["CVE"].append(cve_data)
                    visited["CVE"].add(cve)

    # Get DEFEND data for ATTACK related to this CAPEC
    for attack in ensure_list(capec_data.get("Related_MITRE_ATT&CK")):
        if attack not in visited["ATTACK"]:
            attack_data = cache["ATTACK"].get(attack) or fetch_attack_data(attack)
            cache["ATTACK"][attack] = attack_data
            result["Nodes"]["ATTACK"].append(attack_data)
            visited["ATTACK"].add(attack)
            for defend in ensure_list(attack_data.get("DEFEND")):
                if defend not in visited["DEFEND"]:
                    defend_data = cache["DEFEND"].get(defend) or fetch_defend_data(defend)
                    cache["DEFEND"][defend] = defend_data
                    result["Nodes"]["DEFEND"].append(defend_data)
                    visited["DEFEND"].add(defend)

    return result

def handle_attack_input(attack_id: str) -> Dict[str, Any]:
    """Special case: when starting from ATT&CK ID, don't traverse subtechniques; only go ATTACK -> DEFEND, then CAPEC -> CWE -> CVE."""
    for key in visited:
        visited[key].clear()

    result = {
        "Query": attack_id,
        "Detected_Type": "ATTACK",
        "Nodes": {"CVE": [], "CWE": [], "CAPEC": [], "ATTACK": [], "DEFEND": []},
        "Notes": []
    }

    logger.info(f"\n[+] Building roadmap for {attack_id} (ATTACK mode)...")

    # 1️⃣ Fetch ATTACK node itself
    attack_data = cache["ATTACK"].get(attack_id) or fetch_attack_data(attack_id)
    cache["ATTACK"][attack_id] = attack_data
    result["Nodes"]["ATTACK"].append(attack_data)
    visited["ATTACK"].add(attack_id)

    # 2️⃣ Add all its DEFEND links
    for defend in ensure_list(attack_data.get("DEFEND")):
        if defend not in visited["DEFEND"]:
            defend_data = cache["DEFEND"].get(defend) or fetch_defend_data(defend)
            cache["DEFEND"][defend] = defend_data
            result["Nodes"]["DEFEND"].append(defend_data)
            visited["DEFEND"].add(defend)

    # 3️⃣ Fetch CAPECs mapped to this ATTACK ID
    for capec in ensure_list(attack_data.get("Related_CAPEC")):
        if capec not in visited["CAPEC"]:
            capec_data = cache["CAPEC"].get(capec) or fetch_capec_data(capec)
            cache["CAPEC"][capec] = capec_data
            result["Nodes"]["CAPEC"].append(capec_data)
            visited["CAPEC"].add(capec)
            for cwe in ensure_list(capec_data.get("Related_CWEs")):
                if cwe not in visited["CWE"]:
                    cwe_data = cache["CWE"].get(cwe) or fetch_cwe_data(cwe)
                    cache["CWE"][cwe] = cwe_data
                    result["Nodes"]["CWE"].append(cwe_data)
                    visited["CWE"].add(cwe)
                    # 3️⃣ Fetch data related to CAPEC-CWEs
                    for cve in ensure_list(cwe_data.get("Related_CVEs")):
                        if cve not in visited["CVE"]:
                            cve_data = cache["CVE"].get(cve) or fetch_cve_data(cve)
                            cache["CVE"][cve] = cve_data
                            result["Nodes"]["CVE"].append(cve_data)
                            visited["CVE"].add(cve)

    return result

def handle_defend_input(defend_id: str) -> Dict[str, Any]:
    """Start from a DEFEND ID → retrieve all related ATT&CK techniques, then expand upward through CAPEC, CWE, CVE."""
    # Clear visited sets
    for key in visited:
        visited[key].clear()

    result = {
        "Query": defend_id,
        "Detected_Type": "DEFEND",
        "Nodes": {"CVE": [], "CWE": [], "CAPEC": [], "ATTACK": [], "DEFEND": []},
        "Notes": []
    }

    logger.info(f"\n[+] Building roadmap for {defend_id} (DEFEND mode)...")

    # 1️⃣ DEFEND node
    defend_data = cache["DEFEND"].get(defend_id) or fetch_defend_data(defend_id)
    cache["DEFEND"][defend_id] = defend_data
    result["Nodes"]["DEFEND"].append(defend_data)
    visited["DEFEND"].add(defend_id)

    # 2️⃣ ATTACK nodes mitigated by this defense
    related_attacks = ensure_list(defend_data.get("RELATED_ATTACKS", []))
    logger.info(f"Found {len(related_attacks)} ATT&CK techniques linked to {defend_id}: {related_attacks}")

    for attack_id in related_attacks:
        if attack_id in visited["ATTACK"]:
            continue
        visited["ATTACK"].add(attack_id)

        attack_data = cache["ATTACK"].get(attack_id) or fetch_attack_data(attack_id)
        cache["ATTACK"][attack_id] = attack_data
        result["Nodes"]["ATTACK"].append(attack_data)

        # 3️⃣ CAPEC nodes mapped to this ATTACK
        try:
            ranked = link_nodes(source_description=attack_data.get("Description", ""),source_type="ATTACK", target_type="CAPEC" ,limit=600)
            capec_list = [r["item"].get("CAPEC_ID") for r in ranked]
            logger.info(f"Found {len(capec_list)} CAPECs linked to {attack_id}: {capec_list}")
        except Exception as e:
            capec_list = []
            logger.warning(f"Hybrid CAPEC inference failed for {attack_id}: {e}")

        for capec_id in capec_list:
            if capec_id in visited["CAPEC"]:
                continue
            visited["CAPEC"].add(capec_id)

            capec_data = cache["CAPEC"].get(capec_id) or fetch_capec_data(capec_id)
            cache["CAPEC"][capec_id] = capec_data
            result["Nodes"]["CAPEC"].append(capec_data)

            # 4️⃣ CWE nodes linked to each CAPEC
            for cwe_id in ensure_list(capec_data.get("Related_CWEs", [])):
                if cwe_id in visited["CWE"]:
                    continue
                visited["CWE"].add(cwe_id)

                cwe_data = cache["CWE"].get(cwe_id) or fetch_cwe_data(cwe_id)
                cache["CWE"][cwe_id] = cwe_data
                result["Nodes"]["CWE"].append(cwe_data)

                # 5️⃣ CVE nodes linked to each CWE
                for cve_id in ensure_list(cwe_data.get("Related_CVEs", [])):
                    if cve_id in visited["CVE"]:
                        continue
                    visited["CVE"].add(cve_id)

                    cve_data = cache["CVE"].get(cve_id) or fetch_cve_data(cve_id)
                    cache["CVE"][cve_id] = cve_data
                    result["Nodes"]["CVE"].append(cve_data)

    # 6️⃣ (Optional) Apply CVE limit if configured
    if FETCH_LIMIT is not None:
        result["Nodes"]["CVE"] = result["Nodes"]["CVE"][:FETCH_LIMIT]

    return result

def handle_cpe_input(cpe_id: str) -> Dict[str, Any]:
    for key in visited:
        visited[key].clear()

    logger.info(f"\n[+] Building roadmap for {cpe_id} (ATTACK mode)...")

    result = {
        "Query": cpe_id,
        "Detected_Type": "CPE",
        "Nodes": {"CPE": [], "CVE": [], "CWE": [], "CAPEC": [], "ATTACK": [], "DEFEND": []},
        "Notes": []
    }

    # fetch_cpe_data now returns List[dict]
    cpe_results = cache["CPE"].get(cpe_id)
    if not cpe_results:
        cpe_results = fetch_cpe_data(cpe_id)
        cache["CPE"][cpe_id] = cpe_results

    # --- add each CPE as its own node ---
    for cpe_obj in cpe_results:
        resolved_cpe = cpe_obj.get("CPE_ID")
        if not resolved_cpe:
            continue

        if resolved_cpe in visited["CPE"]:
            continue

        visited["CPE"].add(resolved_cpe)
        result["Nodes"]["CPE"].append(cpe_obj)

        # --- expand CVEs for THIS CPE ---
        for cve in ensure_list(cpe_obj.get("Related_CVEs")):
            if cve in visited["CVE"]:
                continue

            visited["CVE"].add(cve)
            cve_result = handle_cve_input(cve)

            for node_type, nodes in cve_result["Nodes"].items():
                result["Nodes"][node_type].extend(nodes)

    return result

def build_roadmap(identifier: str) -> Dict[str, Any]:
    for key in visited:
        visited[key].clear()

    result = {
        "Query": identifier,
        "Detected_Type": detect_type(identifier),
        "Nodes": {"CPE": [], "CVE": [], "CWE": [], "CAPEC": [], "ATTACK": [], "DEFEND": []},
        "Notes": []
    }

    logger.info(f"\n[+] Building roadmap for {identifier} ({result['Detected_Type']}) ...")

    for key in result["Nodes"]:
        merged = {}
        for node in result["Nodes"][key]:
            if not isinstance(node, dict):
                continue

            # pick the unique ID field for each type
            node_id = (
                    node.get("CVE_ID")
                    or node.get("CWE_ID")
                    or node.get("CAPEC_ID")
                    or node.get("ATTACK")
                    or node.get("DEFEND")
                    or node.get("CPE_ID")
            )
            if not node_id:
                continue

            if node_id not in merged:
                merged[node_id] = node
            else:
                for k, v in node.items():
                    if k not in merged[node_id] or merged[node_id][k] in [None, "-", ""]:
                        merged[node_id][k] = v

        result["Nodes"][key] = list(merged.values())

    return result


def run(user_input: str, mode: str = "default", forced_target_type: str | None = None):
    global FETCH_LIMIT
    # mode -> CVE limit
    if mode == "agg":
        set_linking_config(top_k=20)
    elif mode == "xtrm":
        set_linking_config(top_k=0)
    else:
        set_linking_config(top_k=5)

    start_time = time.time()
    lazy_imports()

    kind = is_keyword_or_text(user_input)
    det_type = detect_type(user_input)  # always defined
    resolved_id = user_input

    # === Determine what to fetch ===
    if kind == "id" or user_input.startswith("-p") or user_input.startswith("-P"):
        if user_input.startswith("-p") or user_input.startswith("-P"):
            det_type = "product"

        if det_type == "CVE":
            roadmap = handle_cve_input(user_input)
        elif det_type == "CWE":
            roadmap = handle_cwe_input(user_input)
        elif det_type == "CAPEC":
            roadmap = handle_capec_input(user_input)
        elif det_type == "ATTACK":
            roadmap = handle_attack_input(user_input)
        elif det_type == "DEFEND":
            roadmap = handle_defend_input(user_input)
        elif det_type == "CPE":
            roadmap = handle_cpe_input(user_input)
        elif user_input.startswith("-p") or user_input.startswith("-P"):
            user_input = user_input[2:].strip()
            roadmap = handle_cpe_input(user_input)
            det_type = "CPE"
        else:
            roadmap = build_roadmap(user_input)
    else:
        # === TEXT / DESCRIPTION PATH ===
        logger.info("[NLP] Resolving free-text input...")
        resolved_id, resolved_type, score, dbg = resolve_text_to_best_id(
            user_input,
            top_k_each=5,
            limit=600,
            forced_target_type=forced_target_type  # pass through from CLI
        )

        if not resolved_id or not resolved_type:
            logger.error("❌ Could not resolve text input to a known entity.")
            raise SystemExit(1)

        logger.info(f"[NLP] Resolved to {resolved_type}:{resolved_id} (score={score:.3f})")

        user_input = resolved_id
        det_type = resolved_type

        # Now re-enter normal ID handling
        if resolved_type == "CVE":
            roadmap = handle_cve_input(resolved_id)
        elif resolved_type == "CWE":
            roadmap = handle_cwe_input(resolved_id)
        elif resolved_type == "CAPEC":
            roadmap = handle_capec_input(resolved_id)
        elif resolved_type == "ATTACK":
            roadmap = handle_attack_input(resolved_id)
        elif resolved_type == "DEFEND":
            roadmap = handle_defend_input(resolved_id)
        else:
            logger.error(f"❌ Unsupported resolved type: {resolved_type}")
            raise SystemExit(1)

        # Preserve original query for output
        roadmap["Query"] = user_input
        roadmap["Detected_Type"] = resolved_type

    logger.info("The type of input: %s", det_type)
    # === Prepare folder and filenames ===
    base_name = re.sub(r'[^A-Za-z0-9_.-]', '_', user_input)

    PROJECT_ROOT = Path(__file__).resolve().parents[2]
    OUTPUTS_DIR = PROJECT_ROOT / "outputs"
    RUN_FOLDER = OUTPUTS_DIR / f"roadmap_{base_name}_output"

    RUN_FOLDER.mkdir(parents=True, exist_ok=True)

    # === Split nodes by type into separate files ===
    per_type = {}
    for node_type, entries in roadmap["Nodes"].items():
        if not entries:
            continue
        filename = f"{node_type}s.json"
        path = RUN_FOLDER / filename
        per_type[node_type] = {"filename": filename, "path": path}

        with path.open("w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)

    unified = {
        "Query": roadmap["Query"],
        "Detected_Type": roadmap["Detected_Type"],
        "Notes": roadmap["Notes"],
        "Nodes": {}
    }

    for node_type, entries in roadmap["Nodes"].items():
        minimal_nodes = []
        for n in entries:
            if not isinstance(n, dict):
                continue

            short = {}

            if "Title" in n:
                short["Title"] = n.get("Title")
            elif "Name" in n:
                short["Title"] = n.get("Name")

            if "Description" in n:
                short["Description"] = n.get("Description")

            source = (
                n.get("Source_Page")
                or n.get("Source_API")
                or n.get("Source_URL")
                or n.get("Source")
                or ""
            )
            if source:
                short["Source"] = source

            if node_type == "CPE":
                short["CPE_ID"] = n.get("CPE_ID")
                short["Part"] = n.get("Part")
                short["Vendor"] = n.get("Vendor")
                short["Product"] = n.get("Product")
                short["Version"] = n.get("Version")
                short["Related_CVEs"] = n.get("Related_CVEs")
            elif node_type == "CVE":
                short["CVE_ID"] = n.get("CVE_ID")
                short["CVSS_Score"] = n.get("CVSS_Score")
                short["Severity"] = n.get("Severity")
                short["Related_CWEs"] = n.get("Related_CWEs")
            elif node_type == "CWE":
                short["CWE_ID"] = n.get("CWE_ID")
                short["Related_CAPEC"] = n.get("Related_CAPEC")
                short["Related_CVEs"] = n.get("Related_CVEs")
            elif node_type == "CAPEC":
                short["CAPEC_ID"] = n.get("CAPEC_ID")
                short["Related_CWEs"] = n.get("Related_CWEs")
                short["Related_MITRE_ATT&CK"] = n.get("Related_MITRE_ATT&CK")
            elif node_type == "ATTACK":
                short["ATTACK"] = n.get("ATTACK")
                short["Related_CAPEC"] = n.get("Related_CAPEC")
                short["DEFEND"] = n.get("DEFEND")
            elif node_type == "DEFEND":
                short["DEFEND"] = n.get("DEFEND")
                short["RELATED_ATTACKS"] = n.get("RELATED_ATTACKS")

            if node_type in per_type:
                short["Details_File"] = per_type[node_type]["filename"]
                node_id = (
                    n.get("CVE_ID")
                    or n.get("CWE_ID")
                    or n.get("CAPEC_ID")
                    or n.get("ATTACK")
                    or n.get("DEFEND")
                    or n.get("CPE_ID")
                    or "unknown"
                )
                short["Details_Path"] = f"{per_type[node_type]['filename']}#{node_id}"

            minimal_nodes.append(short)

        unified["Nodes"][node_type] = minimal_nodes

    PROJECT_ROOT = Path(__file__).resolve().parents[2]
    OUTPUT_DIR = PROJECT_ROOT / "outputs"

    # Ensure outputs directory exists
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Save unified roadmap in outputs folder
    unified_file = RUN_FOLDER / f"roadmap_{base_name}.json"

    with unified_file.open("w", encoding="utf-8") as f:
        json.dump(unified, f, indent=2, ensure_ascii=False)

    runtime = time.time() - start_time

    logger.info("⏱ Completed in %.1fs", runtime)

    total_nodes = sum(len(v) for v in unified["Nodes"].values())
    logger.info("Total nodes generated: %d", total_nodes)

    # Save runtime statistics (append, do not overwrite)
    runtime_file = OUTPUT_DIR / "runtime.txt"

    with runtime_file.open("a", encoding="utf-8") as f:
        f.write(f"{user_input} | {runtime:.3f} | {total_nodes}\n")

    logger.info("✅ Unified roadmap saved to: %s", unified_file)
    for t, meta in per_type.items():
        logger.info("📘 %ss file saved: %s", t, meta["path"])

    # GUI is optional; do not hard-fail CLI if GUI fails
    # try:
    #     from veacor.Visualize import run_app
    #     run_app()
    # except Exception as e:
    #     logger.warning("Visualizer could not be started: %s", e)



    return unified_file



if __name__ == "__main__":
    from veacor.cli import main
    raise SystemExit(main())
