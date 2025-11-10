#!/usr/bin/env python3
"""
Dependencies:
  pip install requests beautifulsoup4 sentence-transformers scikit-learn torch
"""
import re
import requests
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple
from bs4 import BeautifulSoup
import io
import zipfile
import csv
from nltk.corpus import wordnet
from functools import lru_cache
import logging
import os
import pickle
import time

import numpy as np
from sentence_transformers import SentenceTransformer, util
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

logger = logging.getLogger(__name__)


DOMAIN_SYNONYMS = {
    "buffer overflow": ["memory corruption", "stack overflow"],
    "cross site scripting": ["xss"],
    "sql injection": ["injection attack", "database injection"],
    "code injection": ["arbitrary code execution"],
    "race condition": ["concurrency issue", "timing vulnerability"],
    "privilege escalation": ["elevation of privilege"],
    "dos": ["denial of service"],
}



# ----------------------------
# Config
# ----------------------------
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"

# Weighting for hybrid scoring: final = ALPHA * embedding + (1-ALPHA) * tfidf
ALPHA = 0.75   # semantic weight

#----------------------------
#   Caching
#----------------------------
CACHE_DIR = os.path.expanduser("~/.cache/cyberdata")
os.makedirs(CACHE_DIR, exist_ok=True)

def download_with_cache(url: str, filename: str, max_age_days: int = 14) -> bytes:
    """
    Download and locally cache large static datasets like MITRE CSV/XML feeds.
    Returns raw bytes.
    """
    path = os.path.join(CACHE_DIR, filename)
    if os.path.exists(path):
        age_days = (time.time() - os.path.getmtime(path)) / 86400
        if age_days < max_age_days:
            logging.info(f"[CACHE] Using cached {filename} (age={age_days:.1f} days)")
            with open(path, "rb") as f:
                return f.read()

    logging.info(f"[CACHE] Downloading {url} ...")
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    with open(path, "wb") as f:
        f.write(r.content)
    logging.info(f"[CACHE] Saved {filename} to cache")
    return r.content


# ----------------------------
# Utilities
# ----------------------------
def min_max_scale(x: np.ndarray) -> np.ndarray:
    x = np.asarray(x, dtype=float)
    if x.size == 0:
        return x
    xmin, xmax = x.min(), x.max()
    if xmax - xmin < 1e-12:
        return np.zeros_like(x)
    return (x - xmin) / (xmax - xmin)

def normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())

# ----------------------------
# Data fetchers
# ----------------------------

def fetch_cve_batches(batch_size=2000, max_batches=50):
    """Yield CVE batches (newest → older) from NVD API."""
    meta_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
    meta_resp = requests.get(meta_url, timeout=30)
    meta_resp.raise_for_status()
    total_results = meta_resp.json().get("totalResults", 0)
    if total_results == 0:
        raise RuntimeError("Could not determine total CVE count from NVD API")

    start_index = max(total_results - batch_size, 0)
    batches = 0

    logging.info(f"[INFO] Total CVEs: {total_results}. Starting at {start_index} (newest batch).")

    while batches < max_batches and start_index >= 0:
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?resultsPerPage={batch_size}&startIndex={start_index}"
        )
        logging.info(f"[INFO] Fetching CVEs (startIndex={start_index})...")
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        batch = [
            {
                "CVE_ID": item["cve"]["id"],
                "Description": next(
                    (d["value"] for d in item["cve"]["descriptions"]
                     if d["lang"].lower() == "en"), ""
                )
            }
            for item in vulns
        ]

        yield batch

        start_index -= batch_size
        batches += 1
        if start_index < 0:
            break

def fetch_cwe_entries(limit=None):
    """
    Fetch CWE entries (ID + Name + Description) from MITRE's official CSV ZIP feed.
    Source: https://cwe.mitre.org/data/csv/1000.csv.zip
    """

    url = "https://cwe.mitre.org/data/csv/1000.csv.zip"
    data = download_with_cache(url, "1000.csv.zip", max_age_days=14)

    # try:
    #     resp = requests.get(url, timeout=60)
    #     resp.raise_for_status()
    # except Exception as e:
    #     raise RuntimeError(f"Failed to download CWE CSV ZIP: {e}")

    # Extract CSV from ZIP
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        csv_name = [n for n in zf.namelist() if n.endswith(".csv")][0]
        csv_data = io.TextIOWrapper(zf.open(csv_name), encoding="utf-8")
        reader = csv.DictReader(csv_data)

        cwes = []
        for i, row in enumerate(reader):
            cwe_id = row.get("CWE-ID", "").strip()
            name = row.get("Name", "").strip()
            desc = row.get("Extended Description", "").strip()

            if not cwe_id:
                continue

            cwes.append({
                "CWE_ID": f"CWE-{cwe_id}",
                "Name": name,
                "Description": desc
            })

            if limit and len(cwes) >= limit:
                break

    logging.info(f"[INFO] Loaded {len(cwes)} CWE entries from CSV ZIP.")
    return cwes

def fetch_capec_entries(limit=None):
    """
    Fetch CAPEC entries (ID + Description) from MITRE XML ZIP feed.
    Uses caching for each XML ZIP URL.
    """
    urls = [
        ("https://capec.mitre.org/data/xml/views/1000.xml.zip", "capec_1000.xml.zip"),
        ("https://capec.mitre.org/data/xml/capec_v3.9.xml.zip", "capec_v3.9.xml.zip")
    ]
    xml_data = None

    for url, fname in urls:
        try:
            logging.info(f"[INFO] Trying {url} ...")
            data = download_with_cache(url, fname, max_age_days=14)
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                xml_file = [n for n in zf.namelist() if n.endswith(".xml")][0]
                xml_data = zf.read(xml_file)
            logging.info(f"[CACHE] Loaded {xml_file} from cached/remote ZIP")
            break
        except Exception as e:
            logging.error(f"[WARN] Failed to load from {url}: {e}")
            continue

    if not xml_data:
        raise RuntimeError("Unable to fetch CAPEC XML from any source")

    # Parse XML
    ns = {"capec": "http://capec.mitre.org/capec-3"}
    root = ET.fromstring(xml_data)
    capecs = []
    for i, ap in enumerate(root.findall(".//capec:Attack_Pattern", ns)):
        if limit and i >= limit:
            break
        capec_id = f"CAPEC-{ap.attrib.get('ID', '').strip()}"
        desc = ap.findtext("capec:Description", "", ns).strip()
        capecs.append({"CAPEC_ID": capec_id, "Description": desc})

    logging.info(f"Loaded {len(capecs)} CAPEC entries from cached XML ZIP.")
    return capecs

def fetch_attack_entries(limit=500):
    """
    Fetch MITRE ATT&CK technique IDs and titles.
    Cached HTML source reused for 7 days.
    """
    url = "https://attack.mitre.org/techniques/"
    html_bytes = download_with_cache(url, "attack_techniques.html", max_age_days=7)
    soup = BeautifulSoup(html_bytes, "html.parser")

    entries = []
    for a in soup.select("a[href^='/techniques/T']"):
        href = a["href"]
        tid = href.strip("/").split("/")[-1]
        title = a.get_text(" ", strip=True)
        entries.append({"ATTACK_ID": tid, "Description": title})
        if limit and len(entries) >= limit:
            break

    logging.info(f"Loaded {len(entries)} ATT&CK techniques from cache/web.")
    return entries

def fetch_defend_entries(limit=500):
    """
    Fetch MITRE D3FEND technique IDs and descriptions.
    Cached HTML reused for 7 days.
    """
    url = "https://d3fend.mitre.org/techniques/"
    html_bytes = download_with_cache(url, "d3fend_techniques.html", max_age_days=7)
    soup = BeautifulSoup(html_bytes, "html.parser")

    entries = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if "/technique/" in href:
            tid = href.split("/")[-2].replace("d3f:", "")
            desc = a.get_text(" ", strip=True)
            entries.append({"DEFEND_ID": tid, "Description": desc})
            if limit and len(entries) >= limit:
                break

    logging.info(f"Loaded {len(entries)} D3FEND techniques from cache/web.")
    return entries

class HybridMatcher:
    """
    Generic hybrid similarity scorer (semantic embeddings + TF-IDF).
    Works for any cybersecurity data family (CVE, CWE, CAPEC, ATTACK, DEFEND, etc.)
    """

    def __init__(self, alpha=ALPHA, model_name=EMBED_MODEL_NAME):
        self.alpha = alpha
        self.model = SentenceTransformer(model_name)
        self.embed_cache = {}  # in-memory
        self.cache_path = os.path.join(CACHE_DIR, "embeddings.pkl")
        self._load_cache()

    def _load_cache(self):
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, "rb") as f:
                    self.embed_cache = pickle.load(f)
                logging.info(f"[CACHE] Loaded {len(self.embed_cache)} embedding sets")
            except Exception:
                self.embed_cache = {}

    def _save_cache(self):
        try:
            with open(self.cache_path, "wb") as f:
                pickle.dump(self.embed_cache, f)
        except Exception:
            pass

    def expand_synonyms(text: str) -> str:
        text_lower = text.lower()
        for k, syns in DOMAIN_SYNONYMS.items():
            if k in text_lower:
                for s in syns:
                    text_lower += f" {s}"
        return text_lower

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

    def _embed_targets(self, key: str, docs: list[str]) -> np.ndarray:
        """Encode and cache embeddings for dataset key (e.g. CAPEC, CWE)."""
        if key in self.embed_cache:
            return self.embed_cache[key]
        emb = self.model.encode(docs, convert_to_numpy=True, normalize_embeddings=True)
        self.embed_cache[key] = emb
        self._save_cache()
        return emb

    def _embed_scores(self, query: str, docs: List[str]) -> np.ndarray:
        """Compute embedding-based cosine similarities."""
        q_emb = self.model.encode(query, convert_to_tensor=True)
        d_emb = self._embed_targets(getattr(self, "current_target_key", "GENERIC"), docs)
        cos = util.cos_sim(q_emb, d_emb)[0].cpu().numpy()
        return cos

    def rank(self, source_description: str, target_set: List[Dict[str, str]], text_fields: List[str] = None, top_k: int = 5) -> List[Tuple[Dict[str, str], float, float, float]]:
        """
        Rank target entries by hybrid similarity to the source_description.

        Args:
            source_description: text of the source node (e.g. CWE description)
            target_set: list of dicts (each representing a CAPEC/CVE/etc. entry)
            text_fields: which keys from target dicts to concatenate as text
                         (default: ["Name", "Description"])
            top_k: number of top results to return

        Returns:
            [(target_dict, final_score, embed_score, tfidf_score)]
        """
        if not text_fields:
            text_fields = ["Name", "Description"]

        # Build clean target texts
        doc_texts = []
        for t in target_set:
            combined = " ".join(str(t.get(f, "")) for f in text_fields)
            doc_texts.append(normalize_ws(combined))

        source_description = expand_synonyms(source_description)
        doc_texts = [expand_synonyms(t) for t in doc_texts]

        # Compute component similarities
        emb = self._embed_scores(source_description, doc_texts)
        tfidf = self._tfidf_scores(source_description, doc_texts)

        emb_n = min_max_scale(emb)
        tfidf_n = min_max_scale(tfidf)

        # Weighted fusion
        if np.std(emb_n) < 1e-6 and np.std(tfidf_n) > 1e-6:
            final = tfidf_n
        elif np.std(tfidf_n) < 1e-6 and np.std(emb_n) > 1e-6:
            final = emb_n
        else:
            final = self.alpha * emb_n + (1 - self.alpha) * tfidf_n

        len_src = len(source_description.split())
        len_targets = np.array([len(t.split()) for t in doc_texts])
        ratio = len_src / (len_targets + 1e-6)
        length_penalty = np.exp(-0.5 * np.abs(np.log(ratio)))  # penalty 0–1

        final = final * length_penalty

        # Rank and package
        ranked = [
            (target_set[i], float(final[i]), float(emb_n[i]), float(tfidf_n[i]))
            for i in range(len(target_set))
        ]
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked[:top_k]

@lru_cache(maxsize=1000)
def expand_with_synonyms(term: str):
    """
    Expand a word or phrase with synonyms from WordNet.
    Returns a list including the original term.
    """
    synonyms = {term.lower()}
    for syn in wordnet.synsets(term):
        for lemma in syn.lemmas():
            word = lemma.name().replace("_", " ").lower()
            if word != term.lower() and len(word) > 2:
                synonyms.add(word)
    return list(synonyms)

def link_nodes(
    source_description: str,
    target_type: str,
    limit: int = 500,
    threshold: float = 0.8,
    max_retries: int = 3,
    attempt: int = 1
):
    matcher = HybridMatcher()
    target_type = target_type.upper()

    logging.info(f"Attempt {attempt}: Matching → {target_type} (limit={limit})")

    if target_type == "CVE":
        # Stream batches from newest to oldest
        all_matches = []
        for batch in fetch_cve_batches():
            matcher.current_target_key = target_type
            # === Synonym expansion (WordNet + domain) ===
            expanded_terms = []
            for word in source_description.split():
                expanded_terms.extend(expand_with_synonyms(word))
            expanded_text = " ".join(sorted(set(expanded_terms)))
            source_description = HybridMatcher.expand_synonyms(expanded_text)
            logger.debug(f"[NLP] Expanded source description for {target_type}: {expanded_text[:120]}...")
            ranked = matcher.rank(
                source_description=source_description,
                target_set=batch,
                text_fields=["Description"],
                top_k=5
            )
            logger.info(f"[NLP] Top {target_type} matches (with confidence scores):")
            for entry, final_score, emb_score, tfidf_score in ranked[:5]:
                name = entry.get("Name") or entry.get("Description", "")[:60]
                logger.info(
                    f"  → {name} | final={final_score:.3f}, emb={emb_score:.3f}, tfidf={tfidf_score:.3f}"
                )

            # Filter top-scoring results
            strong = [r for r in ranked if r[1] >= 0.7]
            all_matches.extend(strong)
            logging.info(f"Found {len(strong)} strong matches so far.")

            if len(all_matches) >= 5:
                break

        # Keep only top 5 overall
        all_matches.sort(key=lambda x: x[1], reverse=True)
        ranked = all_matches[:5]
        logging.info("\n[RESULTS] Top CVE Matches:")
        for entry, final_score, embed_score, tfidf_score in ranked:
            logging.info(f"  - {entry['CVE_ID']}: final={final_score:.3f}, embed={embed_score:.3f}, tfidf={tfidf_score:.3f}")

    else:
        # Handle all non-CVE types normally
        if target_type == "CWE":
            targets = fetch_cwe_entries(limit)
            text_fields = ["Name", "Description"]
        elif target_type == "CAPEC":
            targets = fetch_capec_entries(limit)
            text_fields = ["Name", "Description"]
        elif target_type == "ATTACK":
            targets = fetch_attack_entries(limit)
            text_fields = ["Description"]
        elif target_type == "DEFEND":
            targets = fetch_defend_entries(limit)
            text_fields = ["Description"]
        else:
            raise ValueError(f"Unknown target type: {target_type}")

        matcher.current_target_key = target_type
        # === Synonym expansion (WordNet + domain) ===
        expanded_terms = []
        for word in source_description.split():
            expanded_terms.extend(expand_with_synonyms(word))
        expanded_text = " ".join(sorted(set(expanded_terms)))
        source_description = HybridMatcher.expand_synonyms(expanded_text)
        logger.debug(f"[NLP] Expanded source description for {target_type}: {expanded_text[:120]}...")
        ranked = matcher.rank(
            source_description=source_description,
            target_set=targets,
            text_fields=text_fields,
            top_k=5
        )
        logger.info(f"[NLP] Top {target_type} matches (with confidence scores):")
        for entry, final_score, emb_score, tfidf_score in ranked[:5]:
            name = entry.get("Name") or entry.get("Description", "")[:60]
            logger.info(
                f"  → {name} | final={final_score:.3f}, emb={emb_score:.3f}, tfidf={tfidf_score:.3f}"
            )

    # Evaluate scores
    scores = [r[1] for r in ranked]
    avg_score = np.mean(scores) if scores else 0.0
    min_score = min(scores or [0])

    logging.info(f"{target_type}: avg={avg_score:.3f}, min={min_score:.3f}")

    # Retry logic (optional)
    if avg_score < threshold and attempt < max_retries and target_type != "CVE":
        new_limit = int(limit * 1.5)
        logging.warning(f"Weak matches (<{threshold:.2f}), retrying with limit={new_limit}...")
        return link_nodes(
            source_description=source_description,
            target_type=target_type,
            limit=new_limit,
            threshold=threshold,
            max_retries=max_retries,
            attempt=attempt + 1
        )

    # Filter by minimum threshold
    min_score_threshold = 0.7
    filtered = [r for r in ranked if r[1] >= min_score_threshold]
    return filtered
