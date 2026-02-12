#!/usr/bin/env python3
"""
Dependencies:
  pip install requests beautifulsoup4 sentence-transformers scikit-learn torch nltk
"""

import re
import requests
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple, Optional
from bs4 import BeautifulSoup
import io
import zipfile
import csv
from functools import lru_cache
import logging
import os
import time
import json
import numpy as np
from sentence_transformers import util, SentenceTransformer
from rag_roadmap.Retrieves.text_cleaning import remove_citations_and_urls
import hashlib

def _to_json_safe(obj):
    """Convert sets → lists so JSON will accept them."""
    if isinstance(obj, dict):
        return {k: _to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, list):
        return [_to_json_safe(v) for v in obj]
    return obj

def _restore_sets(obj):
    """
    Reverse operation: convert certain list fields back into sets
    for fast runtime membership checks.
    """
    if isinstance(obj, dict):
        restored = {}
        for k, v in obj.items():
            if k in ("_tokens", "_name_tokens") and isinstance(v, list):
                restored[k] = set(v)
            else:
                restored[k] = _restore_sets(v)
        return restored

    if isinstance(obj, list):
        return [_restore_sets(v) for v in obj]

    return obj



logger = logging.getLogger(__name__)

_LINK_CACHE = {}

# ------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------
EMBED_MODEL_NAME = "sentence-transformers/multi-qa-mpnet-base-dot-v1"
MIN_SCORE = 0.85
TOP_K = 5


def _hash_text(text: str) -> str:
    """
    Stable hash for long descriptions — avoids storing full text as cache keys.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


# ------------------------------------------------------------
# TOKENIZER
# ------------------------------------------------------------
def tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z]{3,}", text.lower())

# ------------------------------------------------------------
# CACHING
# ------------------------------------------------------------
CACHE_DIR = os.path.expanduser("~/.cache/cyberdata")
os.makedirs(CACHE_DIR, exist_ok=True)
EMBED_DIR = os.path.join(CACHE_DIR, "embeddings")
os.makedirs(EMBED_DIR, exist_ok=True)

def get_or_compute_embeddings(dataset_key: str, docs: List[str], model):
    fpath = os.path.join(EMBED_DIR, f"{dataset_key}.npy")

    if os.path.exists(fpath):
        return np.load(fpath)

    emb = model.encode(
        docs,
        convert_to_numpy=True,
        normalize_embeddings=True,
        show_progress_bar=False,
        batch_size=64
    )
    np.save(fpath, emb)
    return emb

def download_with_cache(url: str, filename: str, max_age_days: int = 7) -> bytes:
    path = os.path.join(CACHE_DIR, filename)

    # Return cached version if fresh
    if os.path.exists(path):
        age_days = (time.time() - os.path.getmtime(path)) / 86400
        if age_days < max_age_days:
            try:
                with open(path, "rb") as f:
                    return f.read()
            except Exception as e:
                logger.error(f"[CACHE] Failed reading cache {filename}: {e}")

    headers = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."),
        "Accept": "application/json,text/*,*/*",
    }

    try:
        r = requests.get(url, headers=headers, timeout=60)
        r.raise_for_status()
        content = r.content
        with open(path, "wb") as f:
            f.write(content)
        return content
    except Exception as e:
        logger.warning(f"[WARN] HTTP fetch failed for {url}: {e}")
        # Try stale cache before failing
        if os.path.exists(path):
            logger.warning(f"[WARN] Using stale cache for {filename}")
            try:
                with open(path, "rb") as f:
                    return f.read()
            except Exception as e2:
                logger.error(f"[CACHE] Failed reading stale cache: {e2}")
        # Last resort: return empty bytes
        return b""

# ------------------------------------------------------------
# UTILITIES
# ------------------------------------------------------------
def min_max_scale(x: np.ndarray) -> np.ndarray:
    x = np.asarray(x, dtype=float)
    if x.size == 0:
        return x
    mn, mx = x.min(), x.max()
    if mx - mn < 1e-12:
        return np.zeros_like(x)
    return (x - mn) / (mx - mn)


def normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())

# ------------------------------------------------------------
# SYNONYM EXPANSION
# ------------------------------------------------------------


# ------------------------------------------------------------
# FETCHERS
# ------------------------------------------------------------
@lru_cache(maxsize=2)
def fetch_cve_batches(batch_size=200, max_batches=5):
    meta_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
    try:
        meta = requests.get(meta_url, timeout=60).json()
    except Exception as e:
        logger.error(f"[ERROR] Failed to query CVE metadata: {e}")
        return []
    total_results = meta.get("totalResults", 0)
    if not total_results:
        return []

    start_index = max(total_results - batch_size, 0)
    batches = 0

    while batches < max_batches and start_index >= 0:
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?resultsPerPage={batch_size}&startIndex={start_index}"
        )
        try:
            data = requests.get(url, timeout=60).json()
        except Exception as e:
            logger.warning(f"[WARN] Failed CVE batch fetch at index {start_index}: {e}")
            break
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        batch = []
        for item in vulns:
            try:
                desc = next(
                    (d["value"] for d in item["cve"]["descriptions"]
                     if d["lang"].lower() == "en"),
                    ""
                )
            except Exception:
                desc = ""
            # batch.append({
            #     "CVE_ID": item["cve"]["id"],
            #     "Description": desc
            # })
            clean = remove_citations_and_urls(normalize_ws(desc.lower()))

            batch.append({
                "CVE_ID": item["cve"]["id"],
                "Description": desc,
                "_clean_desc": clean,
                "_tokens": set(tokenize(clean)),
                "_name": item["cve"]["id"].lower(),
                "_name_emb": GLOBAL_MATCHER.model.encode(item["cve"]["id"].lower(), normalize_embeddings=True, show_progress_bar=False),
                "_length": len(clean.split())
            })

        yield batch

        start_index -= batch_size
        batches += 1

@lru_cache(maxsize=2)
def fetch_cwe_entries(limit=None):
    try:
        data = download_with_cache(
            "https://cwe.mitre.org/data/csv/1000.csv.zip",
            "1000.csv.zip"
        )
        if not data:
            return []

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            csv_name = [n for n in zf.namelist() if n.endswith(".csv")][0]
            reader = csv.DictReader(io.TextIOWrapper(zf.open(csv_name), encoding="utf-8"))
    except Exception as e:
        logger.error(f"[ERROR] Failed to load CWE CSV: {e}")
        return []
    out = []
    for row in reader:
        if row.get("CWE-ID"):
            out.append({
                "CWE_ID": f"CWE-{row['CWE-ID']}",
                "Name": row["Name"],
                "Description": row["Extended Description"]
            })
            if limit and len(out) >= limit:
                break
    return out

@lru_cache(maxsize=2)
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
            if not data:
                return []
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                xml_file = [n for n in zf.namelist() if n.endswith(".xml")][0]
                xml_data = zf.read(xml_file)
            logging.info(f"[CACHE] Loaded {xml_file} from cached/remote ZIP")
            break
        except Exception as e:
            logging.error(f"[WARN] Failed to load from {url}: {e}")
            continue

    if not xml_data:
        logger.error("[ERROR] CAPEC XML unavailable")

    # Parse XML
    ns = {"capec": "http://capec.mitre.org/capec-3"}
    try:
        root = ET.fromstring(xml_data)
    except Exception as e:
        logger.error(f"[ERROR] Failed to parse CAPEC XML: {e}")
        return []
    capecs = []
    for i, ap in enumerate(root.findall(".//capec:Attack_Pattern", ns)):
        if limit and i >= limit:
            break
        capec_id = f"CAPEC-{ap.attrib.get('ID', '').strip()}"
        desc = (
                ap.findtext("capec:Description", "", ns).strip()
                or ap.findtext("capec:Summary", "", ns).strip()
                or ap.findtext("capec:Alternate_Terms", "", ns).strip()
        )

        if not desc:
            desc = ap.attrib.get("Name", "")  # fallback

        capecs.append({"CAPEC_ID": capec_id, "Description": desc})

    logging.info(f"Loaded {len(capecs)} CAPEC entries from cached XML ZIP.")
    return capecs

@lru_cache(maxsize=2)
def fetch_attack_entries(limit=None):
    """
    Fetches ATT&CK Enterprise techniques from MITRE's official GitHub
    STIX 2.1 bundle instead of TAXII (which fails or rate-limits).
    """

    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    try:
        data = download_with_cache(url, "enterprise_attack.json", max_age_days=14)
        if not data:
            return []
        bundle = json.loads(data)
    except Exception as e:
        logger.error(f"[ERROR] Failed loading ATT&CK JSON: {e}")
        return []
    out = []
    count = 0

    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            tid = obj.get("external_references", [{}])[0].get("external_id", "")
            desc = obj.get("description", "").strip()
            name = obj.get("name", "")

            if tid.startswith("T"):
                out.append({
                    "ATTACK_ID": tid,
                    "Name": name,
                    "Description": desc
                })

                count += 1
                if limit and count >= limit:
                    break

    return out

@lru_cache(maxsize=2)
def fetch_defend_entries(limit=500):
    """
    Fetch MITRE D3FEND techniques from the new CSV ontology:
    https://d3fend.mitre.org/ontologies/d3fend.csv

    The CSV contains fields including:
        - d3fend-id
        - description
    """

    url = "https://d3fend.mitre.org/ontologies/d3fend.csv"

    try:
        data = download_with_cache(url, "d3fend.csv", max_age_days=14)
        if not data:
            return []
        text = data.decode("utf-8", errors="ignore")
        reader = csv.DictReader(text.splitlines())
    except Exception as e:
        logger.error(f"[ERROR] Failed loading D3FEND CSV: {e}")
        return []

    out = []

    for row in reader:
        d3id = row.get("d3fend-id") or row.get("ID") or ""
        desc = row.get("Definition") or ""

        if not d3id:
            continue

        out.append({
            "DEFEND_ID": d3id.strip(),
            "Description": desc.strip(),
        })

        if limit and len(out) >= limit:
            break

    return out


# ---------------------------------------
# HYBRID MATCHER
# ------------------------------------------------------------
class HybridMatcher:
    def __init__(self, model_name: str = EMBED_MODEL_NAME):
        self.model = SentenceTransformer(model_name)

    def _embed_targets(self, key: str, docs: List[str]) -> np.ndarray:
        return get_or_compute_embeddings(key, docs, self.model)

    def _semantic_scores(self, query: str, docs: List[str], key: str) -> np.ndarray:
        q = self.model.encode(
            query,
            convert_to_tensor=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        d = self._embed_targets(key, docs)
        cos = util.cos_sim(q, d)[0].cpu().numpy()
        return cos

    def rank(
            self,
            source_clean: str,
            target_set: List[Dict[str, str]],
            text_fields: Optional[List[str]] = None,
            dataset_key: str = "GENERIC",
            top_k = TOP_K,
    ):
        """
        Hybrid ranker with original scoring:
          0.70 * semantic(desc) +
          0.20 * keyword Jaccard(desc) +
          0.05 * SBERT name similarity +
          0.05 * length scaling

        Uses preprocessed fields:
          _clean_desc, _tokens, _name, _length
        """

        if not target_set:
            return []

        # Pre-tokenize source once
        src_tokens = set(tokenize(source_clean))

        # Use preprocessed dataset fields
        docs = [t["_clean_desc"] for t in target_set]
        token_sets = [t["_tokens"] for t in target_set]
        names = [t["_name"] for t in target_set]
        lengths = np.array([t["_length"] for t in target_set])


        # ---------- Semantic similarity ----------
        sem = self._semantic_scores(source_clean, docs, dataset_key)
        sem_n = min_max_scale(sem)

        # ---------- Keyword Jaccard ----------
        keyword_scores = []
        for tokens in token_sets:
            j = len(tokens & src_tokens) / max(1, len(tokens | src_tokens))
            keyword_scores.append(j)
        keyword_n = min_max_scale(keyword_scores)

        # ---------- Name/title similarity (SBERT, original behaviour) ----------
        if not hasattr(self, "_query_cache"):
            self._query_cache = {}

        if source_clean not in self._query_cache:
            self._query_cache[source_clean] = self.model.encode(
                source_clean,
                normalize_embeddings=True,
                show_progress_bar=False
            )
        src_vec = self._query_cache[source_clean]
        name_vecs = np.array([t["_name_emb"] for t in target_set])
        name_boost = util.cos_sim(src_vec, name_vecs)[0].cpu().numpy()
        name_boost = min_max_scale(name_boost)

        # ---------- Length relevance ----------
        length_scale = min_max_scale(np.clip(lengths, 5, 150))

        # ---------- Final weighted score ----------
        final = (
                0.70 * sem_n +  # primary semantic
                0.20 * keyword_n +  # keyword overlap
                0.05 * name_boost +  # SBERT title similarity
                0.05 * length_scale  # description quality scaling
        )

        # ---------- Early-stop top-k ----------
        top_results = []  # list of (final_score, index)

        for i in np.argsort(final)[::-1]:  # same order you already use
            score = float(final[i])

            if score >= MIN_SCORE:  # only accept scores above threshold
                top_results.append((score, i))

            if len(top_results) >= top_k:  # STOP as soon as we have top_k
                break

        # ---------- Return top-k ----------
        #idx_sorted = np.argsort(final)[::-1]
        # Build results from early-stop list
        results = []
        for score, i in top_results:
            percentage = f"{score * 100:.1f}%"
            results.append({
                "item": target_set[i],
                "score": score,
                "percentage": percentage,
            })
            print(f"Score:{score}")
        return results


_raw = {
    "CWE": fetch_cwe_entries(limit=2000),
    "CAPEC": fetch_capec_entries(limit=2000),
    "ATTACK": fetch_attack_entries(limit=2000),
    "DEFEND": fetch_defend_entries(limit=2000),
}

PREPROC_DIR = os.path.join(CACHE_DIR, "preprocessed")
os.makedirs(PREPROC_DIR, exist_ok=True)

def _dataset_cache_path(key: str) -> str:
    return os.path.join(PREPROC_DIR, f"{key.lower()}_preprocessed.json")


def load_preprocessed_dataset(key: str):
    """Load preprocessed dataset from disk if available."""
    path = _dataset_cache_path(key)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return _restore_sets(data)   # <-- convert lists back into sets
        except Exception as e:
            logger.error(f"[CACHE] Failed reading preprocessed dataset {key}: {e}")
    return None


def save_preprocessed_dataset(key: str, dataset):
    """Write preprocessed dataset to cache."""
    path = _dataset_cache_path(key)
    try:
        safe = _to_json_safe(dataset)  # <-- convert sets → lists
        with open(path, "w", encoding="utf-8") as f:
            json.dump(safe, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"[CACHE] Failed storing preprocessed dataset {key}: {e}")


GLOBAL_MATCHER = HybridMatcher()
GLOBAL_DATASETS = {}



GLOBAL_DATASETS = {}

for key, entries in _raw.items():

    # 1️⃣ Try loading preprocessed version
    # 1️⃣ Try loading preprocessed version
    cached = load_preprocessed_dataset(key)
    if cached:

        # 🔥 FIX MISSING FIELDS IN OLD CACHE FILES
        for t in cached:
            # ensure _clean_desc exists
            if "_clean_desc" not in t:
                desc = (t.get("Description") or "").lower()
                desc = remove_citations_and_urls(normalize_ws(desc))
                t["_clean_desc"] = desc

            # ensure _length exists
            if "_length" not in t:
                desc = t.get("_clean_desc") or ""
                t["_length"] = len(desc.split())

            # ensure _tokens exists
            if "_tokens" not in t:
                clean = t.get("_clean_desc", "")
                t["_tokens"] = set(tokenize(clean))

            # ensure _name exists
            if "_name" not in t:
                base = (t.get("Name") or t.get(f"{key}_ID") or "").lower()
                t["_name"] = base

            # ensure _name_tokens exists
            if "_name_tokens" not in t:
                base = t.get("_name", "")
                t["_name_tokens"] = set(tokenize(base))

            if "_name_emb" not in t:
                t["_name_emb"] = GLOBAL_MATCHER.model.encode(t["_name"], normalize_embeddings=True, show_progress_bar=False)

        GLOBAL_DATASETS[key] = cached
        continue

    # 2️⃣ Preprocess dataset for first time
    processed = []
    for t in entries:
        desc = (t.get("Description") or "").lower()
        desc = remove_citations_and_urls(normalize_ws(desc))

        # Dataset-specific truncation
        if key == "CAPEC":
            desc = ". ".join(desc.split(".")[:2])
        elif key == "ATTACK":
            desc = desc.split("\n")[0]
        elif key == "CWE":
            desc = desc[:400]

        t["_clean_desc"] = desc
        t["_tokens"] = set(tokenize(desc))

        base_name = (t.get("Name") or t.get(f"{key}_ID") or "").lower()
        t["_name"] = base_name
        t["_name_tokens"] = set(tokenize(base_name))
        t["_length"] = len(desc.split()) if desc else 0
        t["_name_emb"] = GLOBAL_MATCHER.model.encode(base_name, normalize_embeddings=True, show_progress_bar=False)
        processed.append(t)

    GLOBAL_DATASETS[key] = processed

    # 3️⃣ Save for next run
    save_preprocessed_dataset(key, processed)

def semantic_fallback_link(
        source_description: str,
        source_type: str,
        target_type: str,
        matcher: HybridMatcher,
        threshold: float = MIN_SCORE,
        top_k: int = 5
):
    """
    Unified semantic fallback for ANY mapping:
    source_type → target_type

    Works for:
      CWE ↔ CAPEC
      CAPEC ↔ ATTACK
      ATTACK ↔ DEFEND
      CVE ↔ CWE
      And any other pair supported by your fetchers.

    Automatically:
      - Fetches the correct dataset
      - Cleans description
      - Chooses appropriate text fields
      - Runs semantic similarity
    """

    # Normalize
    source_type = source_type.upper()
    target_type = target_type.upper()
    clean_src = remove_citations_and_urls(
        normalize_ws(source_description)
    ).lower()

    # -----------------------------
    # 1. Select dataset and fields
    # -----------------------------
    if target_type == "CWE":
        targets = [dict(t) for t in GLOBAL_DATASETS[target_type]]
        text_fields = ["Name", "Description"]
        dataset_key = "CWE"

    elif target_type == "CAPEC":
        targets = [dict(t) for t in GLOBAL_DATASETS[target_type]]
        text_fields = ["Description"]
        dataset_key = "CAPEC"

    elif target_type == "ATTACK":
        targets = [dict(t) for t in GLOBAL_DATASETS[target_type]]
        text_fields = ["Description"]
        dataset_key = "ATTACK"

    elif target_type == "DEFEND":
        targets = [dict(t) for t in GLOBAL_DATASETS[target_type]]
        text_fields = ["Description"]
        dataset_key = "DEFEND"


    elif target_type == "CVE":
        # ensure CVE entries have cleaned descriptions
        for t in GLOBAL_DATASETS.get("CVE", []):
            if "_clean_desc" not in t:
                clean = remove_citations_and_urls(normalize_ws((t.get("Description") or "").lower()))
                t["_clean_desc"] = clean
                t["_tokens"] = set(tokenize(clean))
                t["_name"] = (t.get("CVE_ID") or "").lower()

        # CVE uses batches, separate process
        all_matches = []
        for batch in fetch_cve_batches():
            ranked = matcher.rank(
                source_clean=clean_src,
                target_set=batch,
                text_fields=["Description"],
                dataset_key="CVE",
                top_k=top_k  # don't explode ranking size
            )

            strong = [r for r in ranked if r["score"] >= threshold]
            all_matches.extend(strong)

            # stop early if we have enough
            if len(all_matches) >= top_k:
                break

        # return only those above threshold;
        # return empty list if none meet threshold
        return all_matches[:top_k] if all_matches else []


    else:
        raise ValueError(f"Unknown target_type {target_type}")


    # -------------------------------------------------
    # 3. Semantic ranking
    # -------------------------------------------------
    ranked = matcher.rank(
        source_clean=clean_src,
        target_set=targets,
        text_fields=["_clean_desc"],
        dataset_key=dataset_key,
        top_k=top_k
    )

    # keep only above-threshold results
    strong = [r for r in ranked if r["score"] >= threshold]

    # return empty list if none meet threshold
    if not strong:
        return []

    return strong[:top_k]

def link_nodes(
    source_description: str,
    source_type: str,
    target_type: str,
    limit: int = 500,
    threshold: float = MIN_SCORE,
    max_retries: int = 5,
    attempt: int = 1,
    top_k: Optional[int] = None,
    matcher: Optional[HybridMatcher] = None
):
    if top_k is None:
        top_k = TOP_K  # default is 5
    if matcher is None:
        matcher = GLOBAL_MATCHER

    # ---- CACHE KEY ----
    # key = (
    #     _hash_text(source_description),
    #     source_type.upper(),
    #     target_type.upper(),
    #     float(threshold)
    # )
    # ---- CACHE KEY (FIXED: includes top_k and limit) ----
    key = (
        _hash_text(source_description),
        source_type.upper(),
        target_type.upper(),
        float(threshold),
        int(top_k),
        int(limit),
    )

    # ---- RETURN EXISTING RESULT ----
    if key in _LINK_CACHE:
        return _LINK_CACHE[key][:top_k]

    results = semantic_fallback_link(
        source_description=source_description,
        source_type=source_type,
        target_type=target_type,
        matcher=matcher,
        threshold=threshold,
        top_k= top_k
    )

    # retry mechanism
    if target_type.upper() == "CVE" and len(results) < top_k and attempt < max_retries:
        new_limit = int(limit * 1.5)
        return link_nodes(
            source_description,
            source_type,
            target_type,
            limit=new_limit,
            threshold=threshold,
            max_retries=max_retries,
            attempt=attempt + 1,
            top_k = top_k,
            matcher=matcher
        )

    # Add suffix: "XYZ123 - NLP Link"
    for r in results:
        item = r["item"]
        # pick correct ID field dynamically
        for fld in ("CWE_ID", "CAPEC_ID", "ATTACK_ID", "DEFEND_ID", "CVE_ID"):
            if fld in item:
                item[fld] = f"{item[fld]} - NLP Link"
                break

    results = results[:top_k]
    _LINK_CACHE[key] = results

    return results
