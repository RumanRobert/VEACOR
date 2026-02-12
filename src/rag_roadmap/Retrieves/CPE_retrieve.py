#!/usr/bin/env python3
import requests
import time
import logging
from collections import Counter

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

REQUEST_HEADERS = {
    "User-Agent": "cpe-cve-fetcher/5.0",
    # "apiKey": "YOUR_NVD_API_KEY"
}

part_map = {
        "a": "Application",
        "o": "Operating System",
        "h": "Hardware",
    }

logging.basicConfig(level=logging.INFO)


def normalize(text: str) -> str:
    return text.lower().replace(" ", "_")


def parse_cpe_23(cpe: str) -> dict:
    parts = cpe.split(":")
    if len(parts) < 13:
        return {}
    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5],
        "cpe": cpe
    }

def has_version(text: str) -> bool:
    return any(char.isdigit() for char in text)


def discover_cpes(marketing_name: str):
    """
    Discovery phase: keyword search, allow all parts (a/o/h)
    """
    start_index = 0
    discovered = []

    while True:
        params = {
            "keywordSearch": marketing_name,
            "startIndex": start_index
        }

        resp = requests.get(NVD_CPE_API, headers=REQUEST_HEADERS, params=params)

        if resp.status_code == 429:
            retry = int(resp.headers.get("Retry-After", 6))
            time.sleep(retry)
            continue

        resp.raise_for_status()
        data = resp.json()

        for product in data.get("products", []):
            cpe_name = product.get("cpe", {}).get("cpeName")
            parsed = parse_cpe_23(cpe_name)
            if parsed:
                discovered.append(parsed)

        results_per_page = data.get("resultsPerPage", 0)
        total_results = data.get("totalResults", 0)

        start_index += results_per_page
        if start_index >= total_results:
            break

        time.sleep(0.6)

    return discovered


def select_canonical_cpe(cpes: list) -> dict:
    """
    Resolution phase: select concrete part
    """
    if not cpes:
        return {}

    parts = Counter(cpe["part"] for cpe in cpes)

    # If only one part exists, use it
    if len(parts) == 1:
        chosen_part = next(iter(parts))
    else:
        # Choose the most common part
        chosen_part = parts.most_common(1)[0][0]

    for cpe in cpes:
        if cpe["part"] == chosen_part and cpe["version"] == "*":
            return cpe

    return cpes[0]


# def fetch_cpe_data(user_input: str):
#     if not user_input.startswith("cpe:"):
#         discovered = discover_cpes(user_input)
#         canonical = select_canonical_cpe(discovered)
#
#         if not canonical:
#             logging.error("No CPEs resolved")
#             return {
#                 "CPE_ID": None,
#                 "Related_CVEs": [],
#                 "Error": "No CPEs resolved"
#             }
#
#         cpe_id = canonical["cpe"]
#     else:
#         cpe_id = user_input
#
#     logging.info(f"Resolved canonical CPE: {cpe_id}")
#
#     results = []
#     cve_start_index = 0
#
#     while True:
#         params = {
#             "cpeName": cpe_id,
#             "startIndex": cve_start_index
#         }
#
#         resp = requests.get(NVD_CVE_API, headers=REQUEST_HEADERS, params=params)
#
#         if resp.status_code == 429:
#             retry = int(resp.headers.get("Retry-After", 6))
#             time.sleep(retry)
#             continue
#
#         resp.raise_for_status()
#         data = resp.json()
#
#         for vuln in data.get("vulnerabilities", []):
#             cve_id = vuln.get("cve", {}).get("id")
#             if cve_id:
#                 results.append(cve_id)
#
#         results_per_page = data.get("resultsPerPage", 0)
#         total_results = data.get("totalResults", 0)
#
#         cve_start_index += results_per_page
#         if cve_start_index >= total_results:
#             break
#
#         time.sleep(0.6)
#
#     parsed = parse_cpe_23(cpe_id)
#
#     part = part_map.get(parsed.get("part"), "Unknown")
#
#     return {
#         "CPE_ID": cpe_id,
#         "Part": part,
#         "Vendor": parsed.get("vendor"),
#         "Product": parsed.get("product"),
#         "Version": parsed.get("version"),
#         "Related_CVEs": results,
#         "Source_Used": "NVD API"
#     }

def fetch_cpe_data(user_input: str):

    # =========================
    # OLD LOGIC (COMMENTED OUT)
    # =========================

    # if not user_input.startswith("cpe:"):
    #     discovered = discover_cpes(user_input)
    #     canonical = select_canonical_cpe(discovered)
    #
    #     if not canonical:
    #         logging.error("No CPEs resolved")
    #         return {
    #             "CPE_ID": None,
    #             "Related_CVEs": [],
    #             "Error": "No CPEs resolved"
    #         }
    #
    #     cpe_id = canonical["cpe"]
    # else:
    #     cpe_id = user_input

    # =========================
    # NEW LOGIC (UPDATED)
    # =========================

    def score_cpe(cpe: dict, keyword: str) -> int:
        score = 0
        kw = keyword.lower()

        # Prefer non-deprecated
        if not cpe.get("deprecated", False):
            score += 50

        # Prefer vendor/product match
        if cpe.get("vendor") and cpe["vendor"] in kw:
            score += 30

        if cpe.get("product") and cpe["product"] in kw:
            score += 30

        # Prefer concrete versions
        if cpe.get("version") not in ("*", "-", ""):
            score += 20

        # Penalize localized builds
        if ":unknown:unknown:" not in cpe.get("cpe", ""):
            score += 20
        else:
            score -= 10

        return score

    if not user_input.startswith("cpe:"):
        discovered = discover_cpes(user_input)
        version_specified = has_version(user_input)

        if not discovered:
            logging.error("No CPEs resolved")
            return {
                "CPE_IDs": [],
                "Related_CVEs": [],
                "Error": "No CPEs resolved"
            }

        # Rank all discovered CPEs
        ranked = sorted(
            discovered,
            key=lambda c: score_cpe(c, user_input),
            reverse=True
        )

        MAX_CPES = 5  # safety cap

        if version_specified:
            cpe_ids = [
                          cpe["cpe"]
                          for cpe in ranked
                          if cpe.get("version") not in ("*", "-", "")
                      ][:MAX_CPES]

        else:
            # All concrete versions, ranked
            cpe_ids = [
                cpe["cpe"]
                for cpe in ranked
                if cpe.get("version") not in ("*", "-", "")
            ]

    else:
        # User supplied a full CPE
        cpe_ids = [user_input]

    logging.info(f"Resolved CPEs: {len(cpe_ids)}")

    # =========================
    # FETCH CVEs FOR ALL CPEs
    # =========================

    cpe_to_cves = {}

    for cpe_id in cpe_ids:
        logging.info(f"Fetching CVEs for {cpe_id}")
        cve_start_index = 0

        while True:
            params = {
                "cpeName": cpe_id,
                "startIndex": cve_start_index
            }

            resp = requests.get(NVD_CVE_API, headers=REQUEST_HEADERS, params=params)

            if resp.status_code == 429:
                retry = int(resp.headers.get("Retry-After", 6))
                time.sleep(retry)
                continue

            resp.raise_for_status()
            data = resp.json()

            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cve", {}).get("id")
                if cve_id:
                    cpe_to_cves.setdefault(cpe_id, set()).add(cve_id)

            results_per_page = data.get("resultsPerPage", 0)
            total_results = data.get("totalResults", 0)

            cve_start_index += results_per_page
            if cve_start_index >= total_results:
                break

            time.sleep(0.6)

    # =========================
    # METADATA (FROM FIRST CPE)
    # =========================

    results = []

    for cpe_id, cves in cpe_to_cves.items():
        parsed = parse_cpe_23(cpe_id)
        part = part_map.get(parsed.get("part"), "Unknown")

        results.append({
            "CPE_ID": cpe_id,
            "Part": part,
            "Vendor": parsed.get("vendor"),
            "Product": parsed.get("product"),
            "Version": parsed.get("version"),
            "Related_CVEs": sorted(cves),
            "Source_Used": "NVD API"
        })

    return results
