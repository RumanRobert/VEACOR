#!/usr/bin/env python3
"""
CVE -> CAPEC Hybrid Matcher
- Input: CVE ID
- Output: All CAPEC IDs ranked by combined score (embedding + TF-IDF), plus component scores.

Dependencies:
  pip install requests beautifulsoup4 sentence-transformers scikit-learn torch
"""
#TODO make sure this retrieves correctly and also do this for all connections
import re
import requests
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple
from bs4 import BeautifulSoup

import numpy as np
from sentence_transformers import SentenceTransformer, util
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

# ----------------------------
# Config
# ----------------------------
CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_v3.9.xml"
USER_AGENT = "CVE-CAPEC-Hybrid/1.0 (research)"
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"

# Weighting for hybrid scoring: final = ALPHA * embedding + (1-ALPHA) * tfidf
ALPHA = 0.6   # semantic weight
# (You can tune ALPHA to 0.5~0.7; 0.6 is a good default.)

# Optional NVD API key (not required; we mostly use MITRE fallback for old CVEs)
NVD_API_KEY = None  # e.g., "your-nvd-key"


# ----------------------------
# Utilities
# ----------------------------
def min_max_scale(x: np.ndarray) -> np.ndarray:
    """Scale array to 0..1; if constant, return zeros."""
    x = np.asarray(x, dtype=float)
    xmin, xmax = x.min(), x.max()
    if xmax - xmin < 1e-12:
        return np.zeros_like(x)
    return (x - xmin) / (xmax - xmin)


def normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())


# ----------------------------
# Data fetchers
# ----------------------------
def fetch_cve_description(cve_id: str) -> str:
    """
    Fetch CVE description:
      1) Try NVD v2 API JSON
      2) If forbidden/missing/non-JSON → fallback to MITRE HTML
    """
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cve/2.0/{cve_id}"
    headers = {"User-Agent": USER_AGENT}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        resp = requests.get(nvd_url, headers=headers, timeout=20)
        if resp.status_code == 403:
            print("[WARN] NVD 403/rate-limited; using MITRE fallback.")
            return fetch_from_mitre(cve_id)
        # Some old CVEs return HTML “draft” pages instead of JSON
        if "application/json" not in (resp.headers.get("Content-Type") or ""):
            print("[WARN] NVD returned HTML (not JSON); using MITRE fallback.")
            return fetch_from_mitre(cve_id)

        data = resp.json()
        vulns = data.get("vulnerabilities") or []
        if vulns:
            descs = (vulns[0].get("cve") or {}).get("descriptions") or []
            # prefer English
            for d in descs:
                if (d.get("lang") or "").lower() == "en" and d.get("value"):
                    return normalize_ws(d["value"])
            for d in descs:
                if d.get("value"):
                    return normalize_ws(d["value"])

        print("[WARN] NVD JSON lacks usable description; using MITRE fallback.")
        return fetch_from_mitre(cve_id)

    except Exception as e:
        print(f"[WARN] NVD fetch error ({e}); using MITRE fallback.")
        return fetch_from_mitre(cve_id)


def fetch_from_mitre(cve_id: str) -> str:
    """Fetch CVE description from MITRE HTML (handles old and new layouts)."""
    url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    headers = {"User-Agent": "Mozilla/5.0"}
    resp = requests.get(url, headers=headers, timeout=20)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    # --- 1️⃣ Try modern <td colspan="2"> block ---
    td = soup.find("td", colspan="2")
    if td and td.get_text(strip=True):
        return td.get_text(" ", strip=True)

    # --- 2️⃣ Try legacy format with "Description" header ---
    rows = soup.find_all("tr")
    for row in rows:
        th = row.find("th")
        if th and "Description" in th.get_text():
            desc_td = row.find("td")
            if desc_td and desc_td.get_text(strip=True):
                return desc_td.get_text(" ", strip=True)

    # --- 3️⃣ Last fallback: any mention of "Description:" text ---
    text_candidates = soup.stripped_strings
    for text in text_candidates:
        if "description" in text.lower() and len(text.split()) > 5:
            return text

    raise ValueError(f"Description not found on MITRE page for {cve_id}.")


def fetch_capec_entries(limit: int = None) -> List[Dict[str, str]]:
    """
    Fetch CAPEC entries (ID, Name, Description) from official XML.
    If 'limit' is set, only return the first N entries (for speed).
    """
    resp = requests.get(CAPEC_XML_URL, headers={"User-Agent": USER_AGENT}, timeout=40)
    if resp.status_code != 200:
        raise ValueError(f"Failed to fetch CAPEC XML ({resp.status_code}).")
    root = ET.fromstring(resp.content)
    ns = {"capec": "http://capec.mitre.org/capec-3"}

    capecs = []
    for i, ap in enumerate(root.findall(".//capec:Attack_Pattern", ns)):
        if limit is not None and i >= limit:
            break
        capec_id = ap.attrib.get("ID")
        name = ap.attrib.get("Name", "") or ""
        desc = ""
        dtag = ap.find("capec:Description", ns)
        if dtag is not None and dtag.text:
            desc = dtag.text.strip()
        capecs.append({
            "CAPEC_ID": f"CAPEC-{capec_id}",
            "Name": name,
            "Description": desc
        })
    return capecs


# ----------------------------
# Hybrid scorer
# ----------------------------
class HybridCveCapecMatcher:
    def __init__(self, alpha: float = ALPHA, model_name: str = EMBED_MODEL_NAME):
        self.alpha = alpha
        self.model = SentenceTransformer(model_name)

    def _tfidf_scores(self, query: str, docs: List[str]) -> np.ndarray:
        """
        TF-IDF cosine similarities between query text and list of doc texts.
        We build a joint vocabulary on [query]+docs to get comparable vectors.
        """
        texts = [query] + docs
        vec = TfidfVectorizer(
            stop_words="english",
            ngram_range=(1, 2),         # unigrams + bigrams often help for CAPEC terms
            min_df=1,
            sublinear_tf=True,
            norm="l2"
        )
        tfidf = vec.fit_transform(texts)     # shape: (1+N, V)
        qv = tfidf[0:1]                      # (1, V)
        dv = tfidf[1:]                       # (N, V)
        sims = linear_kernel(qv, dv)[0]      # cosine since L2-normalized
        return np.asarray(sims)

    def _embed_scores(self, query: str, docs: List[str]) -> np.ndarray:
        """Embedding cosine similarities between query and docs."""
        q_emb = self.model.encode(query, convert_to_tensor=True)
        d_emb = self.model.encode(docs, convert_to_tensor=True)
        cos = util.cos_sim(q_emb, d_emb)[0].cpu().numpy()   # shape (N,)
        return cos

    def rank(self, cve_text: str, capecs: List[Dict[str, str]]) -> List[Tuple[Dict[str, str], float, float, float]]:
        """
        Returns list of (capec_entry, final_score, embed_score, tfidf_score) sorted desc.
        """
        doc_texts = [f"{c['Name']} — {c['Description']}" for c in capecs]

        # Compute component scores
        emb = self._embed_scores(cve_text, doc_texts)     # [-1..1] typical
        tfidf = self._tfidf_scores(cve_text, doc_texts)   # [0..1] typical

        # Normalize both to 0..1 before fusion to avoid scale dominance
        emb_n = min_max_scale(emb)
        tfidf_n = min_max_scale(tfidf)

        final = self.alpha * emb_n + (1.0 - self.alpha) * tfidf_n

        # Package & sort
        ranked = [
            (capecs[i], float(final[i]), float(emb_n[i]), float(tfidf_n[i]))
            for i in range(len(capecs))
        ]
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked


# ----------------------------
# CLI
# ----------------------------
def main():
    try:
        user = input("Enter CVE ID (default: CVE-2002-0412): ").strip().upper()
    except EOFError:
        user = ""
    cve_id = user or "CVE-2002-0412"

    print(f"\n[+] Resolving CVE description for {cve_id} ...")
    cve_text = fetch_cve_description(cve_id)
    print(f"[i] CVE text (first 200 chars): {cve_text[:200]}...\n")

    print("[+] Loading CAPEC entries (this may take a few seconds) ...")
    capecs = fetch_capec_entries(limit=None)  # set a number (e.g., 300) if you want faster runs

    print("[+] Scoring with hybrid (embeddings + TF-IDF) ...")
    matcher = HybridCveCapecMatcher(alpha=ALPHA, model_name=EMBED_MODEL_NAME)
    ranked = matcher.rank(cve_text, capecs)

    # Print all results
    print("\n📊 CAPEC Ranking (All):")
    print(" Rank |  Final  | Embed  | TF-IDF | CAPEC-ID   | Name")
    print("------+---------+--------+--------+------------+-------------------------")
    for idx, (capec, final_s, emb_s, tfidf_s) in enumerate(ranked, start=1):
        print(f"{idx:>5} | {final_s:>7.3f} | {emb_s:>6.3f} | {tfidf_s:>6.3f} | {capec['CAPEC_ID']:<10} | {capec['Name'][:60]}")

    # Show best
    best_capec, best_final, best_emb, best_tfidf = ranked[0]
    print("\n✅ Best Match")
    print(f"   CAPEC: {best_capec['CAPEC_ID']} — {best_capec['Name']}")
    print(f"   Final: {best_final:.3f}  (Embed: {best_emb:.3f}  TF-IDF: {best_tfidf:.3f})")
    print(f"   Desc:  {normalize_ws(best_capec['Description'])[:300]}...\n")


if __name__ == "__main__":
    main()
