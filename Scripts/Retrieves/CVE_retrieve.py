#!/usr/bin/env python3
"""
cve_fetcher.py

Primary source: CVE.org (CVE AWG API) -> https://cveawg.mitre.org/api/cve/{CVE}
Fallback/enrichment: NVD (scrape) -> https://nvd.nist.gov/vuln/detail/{CVE}

Outputs a JSON-like dict with fields:
- CVE_ID, Title, Description, Published, Updated
- Related_CWEs, CVSS_Score, Severity
- Products_Info (list of {Vendor, Product, Affected_Versions})
- Exploit_Tools (from NVD), Advisories, Solutions, Tools (URLs)
- Source_API, Source_Page, Source_Used
"""

import requests
import json
from bs4 import BeautifulSoup
from collections import defaultdict
import sys
import os

REQUEST_HEADERS = {"User-Agent": "Mozilla/5.0 (cve-fetcher/1.0)"}


def fetch_cve_data(cve_id, timeout=15):
    """
    Fetch from CVE.org (primary). If important fields missing, enrich using NVD scrape.
    Returns a dictionary of extracted fields.
    """
    api_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        resp = requests.get(api_url, timeout=timeout, headers=REQUEST_HEADERS)
    except Exception as e:
        print(f"[WARN] Error contacting CVE API: {e}. Falling back to NVD.")
        return fetch_from_nvd(cve_id)

    if resp.status_code != 200:
        print(f"[WARN] CVE API returned {resp.status_code}. Falling back to NVD.")
        return fetch_from_nvd(cve_id)

    try:
        data = resp.json()
    except ValueError:
        print("[WARN] CVE API returned invalid JSON. Falling back to NVD.")
        return fetch_from_nvd(cve_id)

    cna = data.get("containers", {}).get("cna", {})

    # Basic fields from CVE.org
    title = cna.get("title")
    description = None
    if cna.get("descriptions"):
        # pick first non-empty description
        for d in cna.get("descriptions", []):
            v = d.get("value")
            if v:
                description = v
                break

    published = data.get("cveMetadata", {}).get("datePublished")
    updated = data.get("cveMetadata", {}).get("dateUpdated")

    # CVSS: prefer highest version available in the CNA metrics (try to find any CVSS keys)
    cvss_score_str = None
    severity = None
    metrics = cna.get("metrics", [])
    if metrics:
        # metrics is often a list of dicts; iterate and look for cvss keys
        for metric in metrics:
            # pick keys that look like cvss (case-insensitive)
            candidate_keys = [k for k in metric.keys() if k.lower().startswith("cvss")]
            # prefer order: cvssV4_0, cvssV3_1, cvssV3_0, cvssV2_0 (but detect dynamically)
            pref_order = ["cvssv4_0", "cvssv3_1", "cvssv3_0", "cvssv2_0"]
            # normalize keys to lower to compare
            candidate_keys_sorted = sorted(candidate_keys,
                                           key=lambda x: pref_order.index(x.lower()) if x.lower() in pref_order else len(pref_order))
            for ck in candidate_keys_sorted:
                cvd = metric.get(ck, {})
                score = cvd.get("baseScore")
                sev = cvd.get("baseSeverity") or cvd.get("severity")
                if score is not None:
                    # derive version text
                    version = ck.replace("cvssV", "").replace("cvssv", "").replace("_", ".")
                    cvss_score_str = f"{float(score):.1f} (Version {version})"
                    severity = sev or severity
                    break
            if cvss_score_str:
                break

    # CWE(s)
    cwe = None
    problem_types = cna.get("problemTypes", [])
    if problem_types:
        # problemTypes is usually a list; take first descriptions entry's cweId if present
        for pt in problem_types:
            descs = pt.get("descriptions", []) or []
            for d in descs:
                cwe_id = d.get("cweId")
                if cwe_id:
                    cwe = cwe_id
                    break
            if cwe:
                break

    # References from CNA (tags may include advisory/solution/tool)
    advisories, solutions, tools = [], [], []
    refs = cna.get("references", []) or []
    for ref in refs:
        url = ref.get("url")
        if not url:
            continue
        tags = [t.lower() for t in (ref.get("tags") or [])]
        tagtext = " ".join(tags)
        if "advisory" in tagtext or "advisories" in tagtext:
            advisories.append(url)
        elif "solution" in tagtext or "fix" in tagtext:
            solutions.append(url)
        elif "tool" in tagtext:
            tools.append(url)
        else:
            # If no tags, try to classify from URL or description heuristics
            if any(k in url for k in ["msrc.microsoft.com", "github.com", "advisory", "security.advisory", "security-advisory"]):
                advisories.append(url)
            elif any(k in url for k in ["fix", "patch", "update", "solution"]):
                solutions.append(url)
            elif "tool" in url:
                tools.append(url)
            # else ignore for now

    # --- Products_Info from CVE.org affected[]
    products_info = []
    affected = cna.get("affected", []) or []
    for item in affected:
        vendor = item.get("vendor") or "Unknown"
        product = item.get("product") or None
        versions_list = item.get("versions", []) or []

        affected_versions_readable = []
        for v in versions_list:
            # fields that are seen in various CVE JSON schemas:
            status = (v.get("status") or "").strip()
            # common keys describing ranges
            version = v.get("version")
            less_than = v.get("lessThan") or v.get("versionEndExcluding")
            less_than_eq = v.get("lessThanOrEqual") or v.get("versionEndIncluding")
            greater_than = v.get("greaterThan") or v.get("versionStartExcluding")
            greater_than_eq = v.get("greaterThanOrEqual") or v.get("versionStartIncluding")
            # also direct descriptors
            version_type = v.get("versionType")

            # Build readable text, trying multiple shapes
            txt = None
            if status:
                s = status.lower()
            else:
                s = ""

            # Prefer human-friendly phrasing:
            if s == "affected":
                if version and less_than:
                    txt = f"affected from {version} before {less_than}"
                elif version and less_than_eq:
                    txt = f"affected from {version} up to {less_than_eq}"
                elif greater_than and less_than:
                    txt = f"affected after {greater_than} before {less_than}"
                elif greater_than_eq and less_than_eq:
                    txt = f"affected from {greater_than_eq} up to {less_than_eq}"
                elif version:
                    txt = f"affected version {version}"
                else:
                    # fallback: combine any available fields
                    parts = []
                    for k in ("version", "versionType", "lessThan", "lessThanOrEqual", "greaterThan", "greaterThanOrEqual"):
                        if v.get(k):
                            parts.append(f"{k}:{v.get(k)}")
                    txt = "affected (" + ", ".join(parts) + ")" if parts else "affected (no version info)"
            elif s == "unaffected":
                # show what the version field is if available
                if version:
                    txt = f"unaffected {version}"
                else:
                    txt = "unaffected (no version info)"
            else:
                # unknown status: format the available range information
                if version and less_than:
                    txt = f"{version} - before {less_than}"
                elif greater_than_eq and less_than_eq:
                    txt = f"{greater_than_eq} - {less_than_eq}"
                elif version:
                    txt = f"version {version}"
                else:
                    # if nothing meaningful, try to stringify the dict
                    txt = json.dumps({k: v.get(k) for k in ("status", "version", "lessThan", "lessThanOrEqual",
                                                              "greaterThan", "greaterThanOrEqual", "versionType") if v.get(k)}, ensure_ascii=False)

            if txt:
                affected_versions_readable.append(txt)

        # dedupe affected_versions_readable
        affected_versions_readable = list(dict.fromkeys(affected_versions_readable))

        # merge vendor/product duplicates
        if product is None:
            product = "(no product specified)"
        existing = next((p for p in products_info if p["Vendor"] == vendor and p["Product"] == product), None)
        if existing:
            existing["Affected_Versions"].extend([v for v in affected_versions_readable if v not in existing["Affected_Versions"]])
        else:
            products_info.append({
                "Vendor": vendor,
                "Product": product,
                "Affected_Versions": affected_versions_readable
            })

    # Remove duplicates and normalize lists
    for p in products_info:
        p["Affected_Versions"] = list(dict.fromkeys(p.get("Affected_Versions", [])))

    # Determine which fields are missing and need NVD enrichment
    missing = []
    if not title:
        missing.append("title")
    if not description:
        missing.append("description")
    if not cvss_score_str:
        missing.append("cvss")
    if not cwe:
        missing.append("cwe")
    if not products_info:
        missing.append("products_info")
    # severity could be missing too
    if not severity:
        missing.append("severity")

    nvd_data = {}
    used_nvd = False
    if missing:
        # Enrich missing fields from NVD
        nvd_data = fetch_from_nvd(cve_id)
        used_nvd = True

        # prefer CVE.org values; fill missing ones with NVD
        title = title or nvd_data.get("Title")
        description = description or nvd_data.get("Description")
        cvss_score_str = cvss_score_str or nvd_data.get("CVSS_Score")
        severity = severity or nvd_data.get("Severity")
        cwe = cwe or nvd_data.get("Related_CWEs")
        # if CVE.org had no products_info, use NVD's
        if not products_info and nvd_data.get("Products_Info"):
            products_info = nvd_data.get("Products_Info")

        # merge references: keep CVE.org lists first, then extend with NVD where missing
        if not advisories:
            advisories = nvd_data.get("Advisories", []) or []
        if not solutions:
            solutions = nvd_data.get("Solutions", []) or []
        if not tools:
            tools = nvd_data.get("Tools", []) or []

    # final normalization: unique lists
    advisories = list(dict.fromkeys(advisories))
    solutions = list(dict.fromkeys(solutions))
    tools = list(dict.fromkeys(tools))

    result = {
        "CVE_ID": cve_id,
        "Title": title,
        "Description": description,
        "Published": published,
        "Updated": updated,
        "Related_CWEs": cwe,
        "CVSS_Score": cvss_score_str,
        "Severity": severity,
        "Products_Info": products_info,
        "Exploit_Tools": nvd_data.get("Exploit_Tools") if used_nvd else [],  # exploit tools are typically on NVD
        "Advisories": advisories,
        "Solutions": solutions,
        "Tools": tools,
        "Source_API": f"https://cveawg.mitre.org/api/cve/{cve_id}",
        "Source_Page": nvd_data.get("Source_Page") or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "Source_Used": "CVE.org + NVD enrichment" if used_nvd else "CVE.org only"
    }

    return result


def fetch_from_nvd(cve_id, timeout=20):
    """
    Scrape NVD page for enrichment. Focuses on:
    - CVSS fallback (4.0 → 3.x → 2.0)
    - Severity
    - CWE
    - Products_Info if CVE.org lacks it (best-effort)
    - Exploit_Tools, Advisories, Solutions, Tools (URLs)
    """
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    try:
        resp = requests.get(nvd_url, timeout=timeout, headers=REQUEST_HEADERS)
    except Exception as e:
        print(f"[ERROR] Error fetching NVD page: {e}")
        return {"CVE_ID": cve_id, "Source_Page": nvd_url}

    if resp.status_code != 200:
        print(f"[ERROR] NVD returned status {resp.status_code} for {cve_id}")
        return {"CVE_ID": cve_id, "Source_Page": nvd_url}

    soup = BeautifulSoup(resp.text, "html.parser")

    # Title (near vuln id)
    title = None
    title_tag = soup.find("span", {"data-testid": "page-header-vuln-id"})
    if title_tag:
        # sibling text often contains the title
        sibling = title_tag.find_next_sibling(text=True)
        if sibling:
            title = sibling.strip(" -")

    # Description
    desc = None
    desc_div = soup.find("p", {"data-testid": "vuln-description"})
    if desc_div:
        desc = desc_div.get_text(strip=True)

    # --- CVSS (robust multi-version detection, supports external scores like CISA-ADP) ---
    import re

    cvss_score_str = None
    severity = None

    for version, panel_id in [
        ("4.0", "vuln-cvss4-panel"),
        ("3.x", "vuln-cvss3-panel"),
        ("2.0", "vuln-cvss2-panel"),
    ]:
        panel = soup.find("div", {"data-testid": panel_id})
        if not panel:
            continue

        # Look for any Base Score or numeric CVSS score text within this panel
        # Try to find all span elements that might include numeric scores
        spans = panel.find_all("span")
        found_score = None
        found_severity = None

        for sp in spans:
            text = sp.get_text(strip=True)
            if not text:
                continue
            # Skip "N/A"
            if "N/A" in text:
                continue
            # Detect numeric scores like 4.3, 7.8, 9.1 etc.
            m = re.match(r"^(\d+(\.\d+)?)(?:\s*([A-Z]+))?$", text)
            if m:
                found_score = m.group(1)
                sev = m.group(3)
                if sev:
                    found_severity = sev.title()
                # Stop at the first valid numeric score
                break

        # If not found yet, look for ADP/CISA Base Scores elsewhere in this panel
        if not found_score:
            adp_tags = panel.find_all(string=lambda s: s and "Base Score:" in s)
            for lbl in adp_tags:
                parent = lbl.find_parent()
                if not parent:
                    continue
                val_span = parent.find_next("span")
                if val_span:
                    val_text = val_span.get_text(strip=True)
                    if val_text and "N/A" not in val_text and any(ch.isdigit() for ch in val_text):
                        parts = val_text.split()
                        found_score = parts[0]
                        if len(parts) > 1:
                            found_severity = parts[1].title()
                        break

        if found_score:
            cvss_score_str = f"{found_score} (Version {version})"
            severity = found_severity or severity
            break

    # CWE
    cwe = None
    cwe_table = soup.find("table", {"data-testid": "vuln-CWEs-table"})
    if cwe_table:
        a = cwe_table.find("a", href=True)
        if a:
            cwe = a.get_text(strip=True)
    else:
        # fallback: find strings containing CWE-
        txt = soup.find(string=lambda s: s and "CWE-" in s)
        if txt:
            cwe = txt.strip()

    # Products_Info from NVD configurations table (best-effort)
    products_info = []
    config_table = soup.find("table", {"data-testid": "vuln-configurations-table"})
    if config_table:
        # The NVD HTML structure varies. We'll attempt to find rows/bodies describing vendor/product/version bullets.
        # Find each configuration block (tbody or divs). We'll search for vendor/product cells if present.
        rows = config_table.find_all("tr")
        # We'll collect mapping key -> affected versions list
        temp = {}
        for r in rows:
            tds = r.find_all("td")
            if not tds:
                continue
            # Heuristic: first td may be status, second vendor, third product, fourth versions
            td_texts = [td.get_text(" ", strip=True) for td in tds]
            # If there are at least 3 columns, map them
            if len(td_texts) >= 3:
                status = td_texts[0]
                vendor = td_texts[1] or "Unknown"
                product = td_texts[2] or "(no product specified)"
                version_info = td_texts[3] if len(td_texts) > 3 else ""
                key = (vendor, product)
                if key not in temp:
                    temp[key] = []
                if version_info:
                    temp[key].append(version_info)
            else:
                # attempt to pull bullets/lis
                li = r.find("li")
                if li:
                    text = li.get_text(strip=True)
                    # find surrounding vendor/product by searching parent nodes
                    parent = r.find_parent("tbody") or r.find_parent("table")
                    vendor = "Unknown"
                    product = "(no product specified)"
                    # naive: search for previous header cells
                    prev_vendor = r.find_previous("td", {"data-testid": "vuln-software-vendor"})
                    prev_product = r.find_previous("td", {"data-testid": "vuln-software-product"})
                    if prev_vendor:
                        vendor = prev_vendor.get_text(strip=True) or vendor
                    if prev_product:
                        product = prev_product.get_text(strip=True) or product
                    key = (vendor, product)
                    temp.setdefault(key, []).append(text)
        # convert temp to products_info list
        for (vendor, product), vers in temp.items():
            products_info.append({
                "Vendor": vendor,
                "Product": product,
                "Affected_Versions": list(dict.fromkeys(vers))
            })

    # Exploit tools (often a section text)
    exploit_tools = []
    exploit_section = soup.find(string=lambda s: s and "Tools Used for Exploitation" in s)
    if exploit_section:
        parent_sec = exploit_section.find_parent()
        if parent_sec:
            for a in parent_sec.find_all("a", href=True):
                exploit_tools.append(a["href"])

    # References sections (Advisories / Solutions / Tools)
    advisories, solutions, tools = [], [], []
    # NVD often has "vuln-hyperlinks-section" blocks
    ref_sections = soup.find_all("div", {"data-testid": "vuln-hyperlinks-section"})
    for ref in ref_sections:
        header = ref.find("h4")
        if not header:
            continue
        category = header.text.strip().lower()
        urls = [a["href"] for a in ref.find_all("a", href=True)]
        if "advisories" in category:
            advisories.extend(urls)
        elif "solutions" in category:
            solutions.extend(urls)
        elif "tools" in category:
            tools.extend(urls)
        else:
            # if can't classify, add to advisories as fallback
            advisories.extend(urls)

    # dedupe lists
    advisories = list(dict.fromkeys(advisories))
    solutions = list(dict.fromkeys(solutions))
    tools = list(dict.fromkeys(tools))
    exploit_tools = list(dict.fromkeys(exploit_tools))

    return {
        "CVE_ID": cve_id,
        "Title": title,
        "Description": desc,
        "CVSS_Score": cvss_score_str,
        "Severity": severity,
        "Related_CWEs": cwe,
        "Products_Info": products_info,
        "Exploit_Tools": exploit_tools,
        "Advisories": advisories,
        "Solutions": solutions,
        "Tools": tools,
        "Source_Page": nvd_url
    }


def _save_json(out, cve_id, folder="."):
    """Save JSON to file to folder/CVE-ID.json"""
    os.makedirs(folder, exist_ok=True)
    fname = os.path.join(folder, f"{cve_id}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    return fname


if __name__ == "__main__":
    # Simple CLI: python cve_fetcher.py CVE-2024-9926 [--save folder]
    if len(sys.argv) < 2:
        print("Usage: python cve_fetcher.py CVE-ID [--save folder]")
        sys.exit(1)

    cve = sys.argv[1].strip()
    save_folder = None
    if len(sys.argv) >= 3 and sys.argv[2] == "--save":
        if len(sys.argv) >= 4:
            save_folder = sys.argv[3]
        else:
            save_folder = "."

    result = fetch_cve_data(cve)
    print(json.dumps(result, indent=2, ensure_ascii=False))

    if save_folder is not None:
        path = _save_json(result, cve, folder=save_folder)
        print(f"[SAVED] {path}")
