#!/usr/bin/env python3
"""
ATTACKDEFEND_retrieve.py
------------------------
Unified retriever for MITRE ATT&CK ↔ D3FEND relationships (via the official API).

This version fixes slug creation for D3FEND technique URLs so the human
title part is used (dropping any code like "ABPI" or "D3-ABPI") while
preserving internal hyphens. Example:
  "D3-ABPI - Application-based Process Isolation"
becomes the slug:
  "Application-basedProcessIsolation"
and the URL:
  https://d3fend.mitre.org/technique/d3f:Application-basedProcessIsolation/
"""

import re
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from rag_roadmap.Retrieves.NLP_relationship_finder import link_nodes, GLOBAL_MATCHER
import logging

BASE_URL = "https://d3fend.mitre.org/"
API_URL = "https://d3fend.mitre.org/api/offensive-technique/attack/{tid}.json"

# ---------- Utilities ----------
def normalize_d3_code(inp: str) -> str:
    s = (inp or "").strip().upper().replace(" ", "-").replace("_", "-")
    if s.startswith("D3-"):
        return s
    if re.fullmatch(r"[A-Z0-9-]+", s) and len(s) <= 8:
        return "D3-" + s
    return s

def extract_tids_from_text(text):
    tids = re.findall(r"\bT\d{3,6}(?:\.\d+)?\b", (text or "").upper())
    return sorted(set(tids), key=lambda x: (int(x.split('.')[0][1:]), x))

def extract_d3ids_from_text(text):
    """Extract only real D3- IDs, ignoring ontology tags like 'd3f:'"""
    cleaned = re.sub(r"\bd3f:", "", text or "", flags=re.IGNORECASE)
    d3s = re.findall(r"\bD3-[A-Z0-9]{2,}(?:-[A-Z0-9]+)*\b", cleaned.upper())
    return sorted(set(d3s))

def try_download_json(url):
    r = requests.get(url, timeout=20, headers={"User-Agent": "d3fend-lookup/1.0"})
    r.raise_for_status()
    return r.json()

def find_all_layer_json_urls(page_soup, page_url):
    found = set()
    for a in page_soup.find_all("a", href=True):
        href = a["href"]
        txt = (a.get("title") or "") + " " + (a.get_text() or "")
        if "navigator" in txt.lower() or href.lower().endswith(".json"):
            found.add(urljoin(page_url, href))
    for s in page_soup.find_all("script"):
        txt = s.string or s.get_text() or ""
        for match in re.findall(r"(https?:\/\/[^\s'\"<>]+\.json)", txt):
            found.add(match)
    return sorted(found)

def fetch_attack_data(attack_id: str, recursive=False):
    """Fetch MITRE ATT&CK + D3FEND info for a given technique ID (e.g., 'T1059')."""
    numeral_id = re.sub(r"\s*-\s*NLP\s+Link\s*$", "", attack_id, flags=re.I)
    tid = numeral_id.strip().upper()
    api_url = API_URL.format(tid=tid)
    page_url = f"{BASE_URL}offensive-technique/attack/{tid}/"
    result = {
        "ATTACK": attack_id,
        "DEFEND": set(),
        "Related_CAPEC": set(),
        "Description": None,
        "Platforms": [],
        "Tactic": None,
        "Tactic_Type": None,
        "Version": None,
        "Mitigations": [],
        "Detection_Strategy": []
    }

    headers = {"User-Agent": "attackdefend-lookup/1.0"}

    # --- 1. Try D3FEND API linkages ---
    try:
        resp = requests.get(api_url, timeout=20, headers=headers)
        resp.raise_for_status()
        resp.encoding = "utf-8"
        data = resp.json()
    except Exception as e:
        if e.response is not None and e.response.status_code == 404:
            result["error"] = f"Could not retrieve more information from official sources. Most likely cause by the attack technique being absent on MITRE DEFEND website."
        else:
            result["error"] = f"Failed to fetch D3FEND API: {e}"
        data = {}

    bindings = data.get("off_to_def", {}).get("results", {}).get("bindings", [])
    if bindings:
        for b in bindings:
            for val in b.values():
                if isinstance(val, dict) and isinstance(val.get("value"), str):
                    if val["value"].upper().startswith("D3-"):
                        result["DEFEND"].add(val["value"].upper())
        result["Source_API"] = api_url
    else:
        text_blob = json.dumps(data)
        defences = extract_d3ids_from_text(text_blob)
        result["DEFEND"].update(defences)

    # --- Build correct ATT&CK URL (subtechniques use slash instead of dot)
    if "." in tid:
        # Example: T1499.003 -> T1499/003
        base, sub = tid.split(".")
        attack_url = f"https://attack.mitre.org/techniques/{base}/{sub}/"
        pass
    else:
        attack_url = f"https://attack.mitre.org/techniques/{tid}/"

    try:
        resp = requests.get(attack_url, timeout=20, headers=headers)
        resp.raise_for_status()
        resp.encoding = "utf-8"
        soup = BeautifulSoup(resp.text, "html.parser")

        # --- Title ---
        title_el = soup.find("h1")
        if title_el:
            result["Title"] = title_el.get_text(" ", strip=True)

        # --- Description ---
        desc = soup.find("div", class_=re.compile(r"description-body", re.I))
        if desc:
            result["Description"] = desc.get_text(" ", strip=True)

        if not result.get("Description"):
            try:
                resp = requests.get(
                    f"https://d3fend.mitre.org/offensive-technique/attack/{numeral_id}/",
                    timeout=20,
                    headers=headers
                )
                resp.raise_for_status()
                resp.encoding = "utf-8"
                soup = BeautifulSoup(resp.text, "html.parser")

                # ------------------------------
                # Look for a "Definition" card
                # ------------------------------
                card = soup.find("div", class_="card")

                if card:
                    header = card.find("h2")
                    if header and header.get_text(strip=True).lower() == "definition":
                        text_block = card.find("div", class_="text-justify")
                        if text_block:
                            result["Description"] = text_block.get_text(" ", strip=True)

                # Optional: final fallback if Definition block not found
                if not result.get("Description"):
                    # Try to find *any* <p> inside the card
                    p = card.find("p") if card else None
                    if p:
                        result["Description"] = p.get_text(" ", strip=True)

            except Exception as e:
                logging.error(f"[FALLBACK ERROR] Could not fetch fallback definition for {attack_id}: {e}")

            # Platforms
            m = re.search(r"Platforms:\s*([^\n]+?)(?=Version|Created|Last Modified|$)", text, flags=re.I)
            if m:
                result["Platforms"] = [p.strip() for p in re.split(r"[,;/]", m.group(1)) if p.strip()]

            # Version
            m = re.search(r"Version:\s*([\w.\-]+)", text, flags=re.I)
            if m:
                result["Version"] = m.group(1).strip()

            # Tactic
            m = re.search(r"Tactic:\s*([A-Za-z0-9\s&\-]+)", text, flags=re.I)
            if m:
                result["Tactic"] = m.group(1).strip()

            # Tactic Type
            m = re.search(r"Tactic Type:\s*([A-Za-z0-9\s&\-]+)", text, flags=re.I)
            if m:
                result["Tactic_Type"] = m.group(1).strip()

        # --- Mitigations Section ---
        mit_head = soup.find(lambda tag: tag.name in ["h2", "h3"] and "Mitigations" in tag.get_text())
        if mit_head:
            table = mit_head.find_next("table")
            if table:
                mitigations = []
                for row in table.find_all("tr")[1:]:
                    cells = [td.get_text(" ", strip=True) for td in row.find_all("td")]
                    if any(cells):
                        mitigations.append(" | ".join(cells))
                    pass
                result["Mitigations"] = mitigations
            pass

        # --- Detection Strategy Section ---
        det_head = soup.find(lambda tag: tag.name in ["h2", "h3"] and "Detection" in tag.get_text())
        if det_head:
            det_table = det_head.find_next("table")
            dets = []
            if det_table:
                for row in det_table.find_all("tr")[1:]:
                    cells = [td.get_text(" ", strip=True) for td in row.find_all("td")]
                    if any(cells):
                        dets.append(" | ".join(cells))
                    pass
            else:
                # fallback to paragraph under detection
                p = det_head.find_next("p")
                if p:
                    dets.append(p.get_text(" ", strip=True))
                pass
            result["Detection_Strategy"] = dets
    except Exception as e:
        result["error_attack"] = f"Failed to parse ATT&CK technique page: {e}"

    logging.info(f"Inferring ATTACK→CAPEC links for {tid} via NLP hybrid model")
    print(result["Description"])
    ranked = link_nodes(source_description=result["Description"], source_type="ATTACK", target_type="CAPEC", limit=300, matcher=GLOBAL_MATCHER)
    result["Related_CAPEC"].update([
        r["item"].get("CAPEC_ID", "?")
        for r in ranked
    ])

    logging.info(f"Inferring ATTACK→DEFEND links for {tid} via NLP hybrid model")
    ranked = link_nodes(source_description=result["Description"], source_type="ATTACK", target_type="DEFEND", limit=300, matcher = GLOBAL_MATCHER)
    result["DEFEND"].update([
        r["item"].get("DEFEND_ID", "?")
        for r in ranked
    ])
    result["Source_API"] = api_url
    result["DEFEND"] = sorted(result["DEFEND"])
    result["Related_CAPEC"] = sorted(result["Related_CAPEC"])
    result["Mitigated_by"] = result["DEFEND"]
    result["Source"] = attack_url
    return result

def fetch_defend_data(d3_id: str):
    """Given D3-XXXX return related ATT&CK techniques and description.

    This function uses the homepage autocomplete text to resolve the human-friendly
    technique title, strips any code prefix (like "D3-ABPI" or "ABPI") and builds a
    slug that preserves internal hyphens but removes spaces:
      "Application-based Process Isolation" -> "Application-basedProcessIsolation"
    """
    d3_id = re.sub(r"\s*-\s*NLP\s+Link\s*$", "", d3_id, flags=re.I)
    identifier = normalize_d3_code(d3_id)
    result = {"DEFEND": identifier, "RELATED_ATTACKS": [], "LOOKUP_FLOW": ""}

    headers = {"User-Agent": "d3fend-lookup/1.0"}

    # 1) Fetch homepage to find autocomplete options
    try:
        home = requests.get(BASE_URL, timeout=20, headers=headers)
        home.raise_for_status()
        home_soup = BeautifulSoup(home.text, "html.parser")
    except Exception as e:
        result["error"] = f"Failed to load D3FEND homepage: {e}"
        return result

    # 2) Heuristic: collect candidate strings that contain the D3 code and a title
    autocomplete_input = home_soup.find("input", {"class": re.compile(r".*autocomplete-input.*")})
    candidates = []
    if autocomplete_input:
        for el in home_soup.find_all(text=re.compile(r"\bD3-[A-Z0-9-]+\b", flags=re.I)):
            text = el.strip()
            if not text:
                continue
            text_norm = " ".join(text.split())
            if identifier in text_norm.upper() or re.search(rf"\b{re.escape(identifier)}\b", text_norm, flags=re.I):
                candidates.append(text_norm)
        for el in home_soup.find_all(["a", "li", "div", "span"]):
            txt = (el.get_text(" ", strip=True) or "").strip()
            if not txt:
                continue
            if identifier in txt.upper() and "D3-" in txt.upper():
                candidates.append(txt)
    # dedupe while preserving order
    seen = set()
    candidates = [c for c in candidates if not (c in seen or seen.add(c))]

    found_title = None
    slug = None
    technique_url = None

    if candidates:
        first = candidates[0].strip()
        result["AUTOCOMPLETE_MATCH"] = first
        # Strip prefix like "D3-ABPI - " or "ABPI - "
        clean_name = re.sub(r'^(?:D3-)?[A-Z0-9]+(?:\s*[-–—]\s*|\s+)', '', first, flags=re.I).strip()
        if not clean_name or re.match(r'^[A-Z0-9-]+$', clean_name):
            parts = re.split(r'\s*[-–—]\s*', first, maxsplit=1)
            if len(parts) == 2:
                clean_name = parts[1].strip()
        if not clean_name:
            clean_name = first

        # Keep internal hyphens, remove spaces
        slug = "".join(re.split(r'\s+', clean_name))
        technique_url = f"{BASE_URL}technique/d3f:{slug}/"

        result["LOOKUP_FLOW"] = "autocomplete-page-scan"
        result["Title"] = clean_name
        result["TECHNIQUE_URL"] = technique_url

    if not technique_url:
        technique_url = f"{BASE_URL}technique/{identifier}/"
        result["LOOKUP_FLOW"] = "fallback-direct-technique-url"

    # 5) Fetch technique page
    page = None
    try:
        resp = requests.get(technique_url, timeout=20, headers=headers)
        resp.raise_for_status()
        page = resp
    except Exception as e_primary:
        if slug:
            alt_slug = slug[0].lower() + slug[1:] if len(slug) > 0 else slug
            alt_url = f"{BASE_URL}technique/d3f:{alt_slug}/"
            try:
                resp_alt = requests.get(alt_url, timeout=20, headers=headers)
                resp_alt.raise_for_status()
                page = resp_alt
                technique_url = alt_url
                result["TECHNIQUE_URL_ALT_TRIED"] = alt_url
            except Exception:
                result["error"] = f"Failed to fetch technique page {technique_url}: {e_primary}"
                return result
        else:
            result["error"] = f"Failed to fetch technique page {technique_url}: {e_primary}"
            return result

    soup = BeautifulSoup(page.text, "html.parser")

    # 6) Extract JSONs and pull ATT&CK IDs + definition
    json_urls = find_all_layer_json_urls(soup, technique_url)
    if not json_urls:
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.lower().endswith(".json"):
                json_urls.append(urljoin(technique_url, href))

    found_tids = set()
    definition = None
    for jurl in sorted(set(json_urls)):
        try:
            jdata = try_download_json(jurl)
            text_blob = json.dumps(jdata)
            if not definition and isinstance(jdata, dict):
                for key in ("description", "definition", "summary", "desc", "descriptionShort"):
                    if key in jdata and isinstance(jdata[key], str):
                        definition = jdata[key]
                        break
                if not definition:
                    for v in jdata.values():
                        if isinstance(v, str) and len(v) > 50 and "attack" not in v.lower():
                            definition = v
                            break
            for tid in extract_tids_from_text(text_blob):
                found_tids.add(tid)
        except Exception:
            continue

    if not found_tids:
        for tid in extract_tids_from_text(page.text):
            found_tids.add(tid)

    # --- Extract ONLY the definition under <h2>Definition</h2> ---
    def_h2 = soup.find(lambda tag: tag.name in ["h2", "h3"] and "definition" in tag.get_text(strip=True).lower())

    definition = None

    if def_h2:
        # Nodes until the next H2/H3
        definition_parts = []
        for sib in def_h2.find_next_siblings():
            # Stop at the next section header
            if sib.name in ["h2", "h3"]:
                break

            # Only capture meaningful text from <p> or <div>
            if sib.name in ["p", "div"]:
                text = sib.get_text(" ", strip=True)
                if text:
                    definition_parts.append(text)

        if definition_parts:
            definition = "\n\n".join(definition_parts)

    # Fallback – if the <h2>Definition</h2> block was missing
    if not definition:
        descr_el = soup.find(lambda tag: tag.name in ("p", "div") and tag.get_text() and len(tag.get_text()) > 80)
        if descr_el:
            definition = descr_el.get_text(" ", strip=True)[:2000]

    result["RELATED_ATTACKS"] = sorted(
        set(result["RELATED_ATTACKS"])
    )
    if definition:
        result["Description"] = definition

    result["Source"] = technique_url
    # ✅ Assign readable name for D3FEND technique
    if "Title" in result:
        result["Title"] = result["Title"]
    else:
        try:
            h1 = soup.find("h1")
            if h1:
                result["Title"] = h1.get_text(strip=True)
        except Exception:
            result["Title"] = None

    logging.info(f"Inferring DEFEND→ATTACK links for {identifier} via NLP hybrid model")

    ranked = link_nodes(
        definition,
        "DEFEND",
        "ATTACK",
        limit=300,
        top_k= 10,
        matcher=GLOBAL_MATCHER
    )
    if ranked:
        result["RELATED_ATTACKS"].extend([
            r["item"].get("ATTACK_ID", "?")
            for r in ranked
        ])
    else:
        logging.info(f"No RELATED_ATTACKS found above threshold")

    return result
