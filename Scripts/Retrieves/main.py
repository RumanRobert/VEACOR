#!/usr/bin/env python3
import re
import json
import sys
import time
from typing import Dict, Any
import os
import logging


# --- SYSTEM PATH ---
sys.path.append(os.path.dirname(__file__))
# === Import retrievers ===
from CVE_retrieve import fetch_cve_data
from CWE_retrieve import fetch_cwe_data
from CAPEC_retrieve import fetch_capec_data
from ATTACKDEFEND_retrieve import fetch_attack_data, fetch_defend_data
from keyword_search import search_cwe
from LLM import extract_keyword


from NLP_relationship_finder import link_nodes

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
CVE_LIMIT = 5  # default value; can be changed by CLI flag


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

    # handle weird prefixes like "NVD-CWE-79"
    if "CWE-" in s:
        return "CWE"
    if "CAPEC-" in s:
        return "CAPEC"

    return "UNKNOWN"


# === Global visited registry ===
visited = {"CVE": set(), "CWE": set(), "CAPEC": set(), "ATTACK": set(), "DEFEND": set()}
# === Global cache to avoid duplicate fetches ===
cache = {"CVE": {}, "CWE": {}, "CAPEC": {}, "ATTACK": {}, "DEFEND": {}}


def convert_sets(obj):
    if isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, dict):
        return {k: convert_sets(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_sets(v) for v in obj]
    else:
        return obj


def build_recursive(identifier: str, result: Dict[str, Any], direction="down", upward_only=False):
    """Traverse one logical chain only, depending on the input type (no infinite loops)."""
    id_upper = identifier.strip().upper()
    node_type = detect_type(id_upper)

    if node_type == "UNKNOWN":
        result["Notes"].append(f"Skipped unknown ID format: {identifier}")
        return

    # avoid duplicates
    if id_upper in visited.get(node_type, set()):
        return
    visited[node_type].add(id_upper)

    # === CVE: go CVE → CWE → CAPEC → ATTACK → DEFEND ===
    if node_type == "CVE":
        data = cache["CVE"].get(id_upper) or fetch_cve_data(id_upper)
        cache["CVE"][id_upper] = data

        result["Nodes"]["CVE"].append(data)

        for cwe in ensure_list(data.get("Related_CWEs")):
            cwe_data = cache["CWE"].get(cwe) or fetch_cwe_data(cwe)
            cache["CWE"][cwe] = cwe_data
            result["Nodes"]["CWE"].append(cwe_data)

            for capec in ensure_list(cwe_data.get("Related_CAPEC")):
                capec_data = cache["CAPEC"].get(capec) or fetch_capec_data(capec)
                cache["CAPEC"][capec] = capec_data
                result["Nodes"]["CAPEC"].append(capec_data)

                for attack in ensure_list(capec_data.get("Related_MITRE_ATT&CK")):
                    attack_data = cache["ATTACK"].get(attack) or fetch_attack_data(attack)
                    cache["ATTACK"][attack] = attack_data
                    result["Nodes"]["ATTACK"].append(attack_data)

                    for defend in ensure_list(attack_data.get("DEFEND")):
                        defend_data = cache["DEFEND"].get(defend) or fetch_defend_data(defend)
                        cache["DEFEND"][defend] = defend_data
                        result["Nodes"]["DEFEND"].append(defend_data)

    # === CWE: go CWE → CVE → CAPEC → ATTACK → DEFEND ===
    elif node_type == "CWE":
        data = fetch_cwe_data(id_upper)
        result["Nodes"]["CWE"].append(data)

        # CVEs
        for cve in ensure_list(data.get("Related_CVEs")):
            cve_data = fetch_cve_data(cve)
            result["Nodes"]["CVE"].append(cve_data)

        # CAPECs
        capec_list = ensure_list(data.get("Related_CAPEC"))
        if not capec_list and data.get("Inherited_CAPEC"):
            capec_list = ensure_list(data["Inherited_CAPEC"].get("CAPECs", []))

        for capec in capec_list:
            capec_data = fetch_capec_data(capec)
            result["Nodes"]["CAPEC"].append(capec_data)

            # ATT&CK
            for attack in ensure_list(capec_data.get("Related_MITRE_ATT&CK")):
                attack_data = fetch_attack_data(attack)
                result["Nodes"]["ATTACK"].append(attack_data)

                for defend in ensure_list(attack_data.get("DEFEND")):
                    defend_data = fetch_defend_data(defend)
                    result["Nodes"]["DEFEND"].append(defend_data)

    # === CAPEC: go CAPEC → CWE → CVE → ATTACK → DEFEND ===
    elif node_type == "CAPEC":
        data = fetch_capec_data(id_upper)
        result["Nodes"]["CAPEC"].append(data)

        for cwe in ensure_list(data.get("Related_CWEs")):
            cwe_data = fetch_cwe_data(cwe)
            result["Nodes"]["CWE"].append(cwe_data)

            for cve in ensure_list(cwe_data.get("Related_CVEs")):
                cve_data = fetch_cve_data(cve)
                result["Nodes"]["CVE"].append(cve_data)

        # Only expand down into ATTACK/DEFEND if we're not in upward-only mode
        if not upward_only:
            for attack in ensure_list(data.get("Related_MITRE_ATT&CK")):
                attack_data = fetch_attack_data(attack)
                result["Nodes"]["ATTACK"].append(attack_data)

                for defend in ensure_list(attack_data.get("DEFEND")):
                    defend_data = fetch_defend_data(defend)
                    result["Nodes"]["DEFEND"].append(defend_data)


    # === ATTACK: go ATTACK → DEFEND ===
    elif node_type == "ATTACK":
        # Fetch and store ATTACK data
        data = cache["ATTACK"].get(id_upper) or fetch_attack_data(id_upper)
        cache["ATTACK"][id_upper] = data
        result["Nodes"]["ATTACK"].append(data)


        capec_ids = []
        try:
            logger.info(f"No explicit CAPEC links for {id_upper}, inferring via NLP model...")
            ranked = link_nodes(data.get("Description", ""), "CAPEC", limit=600)
            capec_ids = [r[0].get("CAPEC_ID") for r in ranked[:5]]
            logger.info(f"Found {len(capec_ids)} inferred CAPECs for {id_upper}: {capec_ids}")
        except Exception as e:
            capec_ids = []
            result["Notes"].append(f"CAPEC inference failed for {id_upper}: {e}")
            logger.warning(f"CAPEC NLP inference failed for {id_upper}: {e}")

        # Traverse discovered CAPECs upward → downward
        for capec in ensure_list(capec_ids):
            build_recursive(capec, result, direction="down", upward_only=True)

        # 🔄 Continue to DEFEND nodes as before
        for defend in ensure_list(data.get("DEFEND")):
            defend_data = cache["DEFEND"].get(defend) or fetch_defend_data(defend)
            cache["DEFEND"][defend] = defend_data
            result["Nodes"]["DEFEND"].append(defend_data)

    # === DEFEND: go DEFEND → ATTACK ===
    elif node_type == "DEFEND":
        data = fetch_defend_data(id_upper)
        result["Nodes"]["DEFEND"].append(data)

        for attack in ensure_list(data.get("RELATED_ATTACKS")):
            attack_data = fetch_attack_data(attack)
            result["Nodes"]["ATTACK"].append(attack_data)


# === Main entry ===
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
    attack_data = fetch_attack_data(attack_id)
    result["Nodes"]["ATTACK"].append(attack_data)
    visited["ATTACK"].add(attack_id)

    # 2️⃣ Add all its DEFEND links
    for defend in ensure_list(attack_data.get("DEFEND")):
        if defend not in visited["DEFEND"]:
            defend_data = fetch_defend_data(defend)
            result["Nodes"]["DEFEND"].append(defend_data)
            visited["DEFEND"].add(defend)

    # 3️⃣ Fetch CAPECs mapped to this ATTACK ID
    try:
        capec_list = link_nodes( result["Nodes"]["ATTACK"][0]["Description"],"CAPEC")
        logger.info(f"Found {len(capec_list)} CAPECs linked to {attack_id}: {capec_list}")
    except Exception as e:
        capec_list = []
        result["Notes"].append(f"CAPEC lookup failed for {attack_id}: {e}")

    # 4️⃣ For each CAPEC, treat it like input (CAPEC → CWE → CVE → ATTACK → DEFEND)
    for capec_id in capec_list:
        if capec_id in visited["CAPEC"]:
            continue
        build_recursive(capec_id, result, direction="down", upward_only=True)

    # 5️⃣ Apply CVE limit if configured
    if CVE_LIMIT is not None:
        result["Nodes"]["CVE"] = result["Nodes"]["CVE"][:CVE_LIMIT]

    return result




def build_roadmap(identifier: str) -> Dict[str, Any]:
    for key in visited:
        visited[key].clear()

    result = {
        "Query": identifier,
        "Detected_Type": detect_type(identifier),
        "Nodes": {"CVE": [], "CWE": [], "CAPEC": [], "ATTACK": [], "DEFEND": []},
        "Notes": []
    }

    logger.info(f"\n[+] Building roadmap for {identifier} ({result['Detected_Type']}) ...")

    # start traversal depending on type
    if result["Detected_Type"] == "DEFEND":
        build_recursive(identifier, result, direction="up")
    else:
        build_recursive(identifier, result, direction="down")

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
            )
            if not node_id:
                continue

            if node_id not in merged:
                merged[node_id] = node
            else:
                # merge fields: keep longer or non-empty versions
                for k, v in node.items():
                    if k not in merged[node_id] or merged[node_id][k] in [None, "-", ""]:
                        merged[node_id][k] = v

        result["Nodes"][key] = list(merged.values())

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
            ranked = link_nodes(attack_data.get("Description", ""), "CAPEC", limit=600)
            capec_list = [r[0].get("CAPEC_ID") for r in ranked[:5]]
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
    if CVE_LIMIT is not None:
        result["Nodes"]["CVE"] = result["Nodes"]["CVE"][:CVE_LIMIT]

    return result



def main():
    global CVE_LIMIT

    # Handle CLI arguments and optional flags
    if len(sys.argv) > 1:
        user_input = sys.argv[1]
        if len(sys.argv) > 2:
            flag = sys.argv[2].lower()
            if flag == "-agg":
                CVE_LIMIT = 20
            elif flag == "-xtrm":
                CVE_LIMIT = None
    else:
        user_input = input("Enter CVE/CWE/CAPEC/ATTACK/D3FEND ID or keyword/text: ").strip()

    start_time = time.time()
    kind = is_keyword_or_text(user_input)

    # === Determine what to fetch ===
    if kind == "id":
        det_type = detect_type(user_input)
        if det_type == "ATTACK":
            roadmap = handle_attack_input(user_input)
        elif det_type == "DEFEND":
            roadmap = handle_defend_input(user_input)
        else:
            roadmap = build_roadmap(user_input)
    elif kind == "keyword":
        user_input = search_cwe(user_input)
        roadmap = build_roadmap(user_input)
    elif kind == "text":
        user_input = extract_keyword(user_input)
        id = search_cwe(user_input)
        roadmap = build_roadmap(id)
        user_input = id
    else:
        logger.error("❌ Invalid input format.")
        sys.exit(1)

    # === Prepare folder and filenames ===
    base_name = re.sub(r'[^A-Za-z0-9_.-]', '_', user_input)
    folder = f"roadmap_{base_name}_output"
    os.makedirs(folder, exist_ok=True)

    # === Split nodes by type into separate files ===
    per_type = {}
    for node_type, entries in roadmap["Nodes"].items():
        if not entries:
            continue
        filename = f"{node_type}s.json"
        path = os.path.join(folder, filename)
        per_type[node_type] = {"filename": filename, "path": path}

        # Write full node data for that type
        with open(path, "w", encoding="utf-8") as f:
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

            # --- include shared descriptive fields ---
            if "Title" in n:
                short["Title"] = n.get("Title")
            elif "Name" in n:
                short["Title"] = n.get("Name")

            if "Description" in n:
                short["Description"] = n.get("Description")

            # --- include any available Source fields ---
            source = (
                n.get("Source_Page")
                or n.get("Source_API")
                or n.get("Source_URL")
                or n.get("Source")
                or ""
            )
            if source:
                short["Source"] = source

            # --- type-specific fields ---
            if node_type == "CVE":
                short["CVE_ID"] = n.get("CVE_ID")
                short["CVSS_Score"] = n.get("CVSS_Score")
                short["Severity"] = n.get("Severity")
                short["Related_CWEs"] = n.get("Related_CWEs")
            elif node_type == "CWE":
                short["CWE_ID"] = n.get("CWE_ID")
                short["Related_CAPEC"] = n.get("Related_CAPEC")
            elif node_type == "CAPEC":
                short["CAPEC_ID"] = n.get("CAPEC_ID")
                short["Related_CWEs"] = n.get("Related_CWEs")
                short["Related_MITRE_ATT&CK"] = n.get("Related_MITRE_ATT&CK")
            elif node_type == "ATTACK":
                short["ATTACK"] = n.get("ATTACK")
                short["DEFEND"] = n.get("DEFEND")
            elif node_type == "DEFEND":
                short["DEFEND"] = n.get("DEFEND")
                short["RELATED_ATTACKS"] = n.get("RELATED_ATTACKS")

            # --- hyperlink to detailed file ---
            if node_type in per_type:
                short["Details_File"] = per_type[node_type]["filename"]
                node_id = (
                    n.get("CVE_ID")
                    or n.get("CWE_ID")
                    or n.get("CAPEC_ID")
                    or n.get("ATTACK")
                    or n.get("DEFEND")
                    or "unknown"
                )
                short["Details_Path"] = f"{per_type[node_type]['filename']}#{node_id}"

            minimal_nodes.append(short)

        unified["Nodes"][node_type] = minimal_nodes

    # === Save unified roadmap ===
    unified_file = os.path.join(folder, f"roadmap_{base_name}.json")
    with open(unified_file, "w", encoding="utf-8") as f:
        json.dump(unified, f, indent=2, ensure_ascii=False)

    # === Summary ===
    logger.info(f"\n✅ Unified roadmap saved to: {unified_file}")
    for t, meta in per_type.items():
        logger.info(f"📘 {t}s file saved: {meta['path']}")
    logger.info(f"⏱ Completed in {time.time() - start_time:.1f}s")




if __name__ == "__main__":
    main()
