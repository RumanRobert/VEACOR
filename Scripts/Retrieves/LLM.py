#!/usr/bin/env python3
import logging
import spacy
from sentence_transformers import SentenceTransformer
from keybert import KeyBERT
from collections import Counter
from typing import List

# Load NLP models (ensure en_core_web_sm and sentence-transformers are installed)
nlp = spacy.load("en_core_web_sm", disable=["ner"])
embedder = SentenceTransformer("all-MiniLM-L6-v2")
kw_model = KeyBERT(model=embedder)

# Generic stopwords we don't want as keywords
GENERIC_STOPWORDS = {
    "security", "attack", "system", "value", "application", "process",
    "service", "information", "malicious", "user", "data", "input",
    "program", "code", "execute", "action", "issue", "software", "behavior",
    "values", "errors", "adversary", "threat", "access", "event", "events"
}

# Authentication words to avoid picking as keywords
AUTH_WORDS = {"login", "logon", "credential", "credentials", "session", "signin", "signon"}

# Words that should force the keyword to "logging"
LOG_VARIANTS = {"log", "logs", "logged", "logging", "logfile", "logfiles", "loggable"}

def normalize(word: str) -> str:
    if not word:
        return ""
    w = word.lower().strip()
    if w in LOG_VARIANTS:
        return "logging"
    return w

def extract_meaningful_words(text: str) -> List[str]:
    doc = nlp(text.lower())
    words = []
    for token in doc:
        if token.is_stop or token.is_punct or token.like_num:
            continue
        lemma = token.lemma_.strip()
        if lemma in GENERIC_STOPWORDS:
            continue
        if lemma in AUTH_WORDS:
            # skip auth words from candidate list (they'll be ignored)
            continue
        if token.pos_ in {"NOUN", "PROPN"} and len(lemma) > 2:
            words.append(lemma)
    return words

def extract_keyword(text: str) -> str:
    text = (text or "").strip()
    if not text:
        return ""

    # 1) Deterministic short-circuit: if any log-variant present -> "logging"
    doc = nlp(text.lower())
    for token in doc:
        if token.lemma_ in LOG_VARIANTS:
            return "logging"

    # 2) Otherwise, build candidate list excluding auth/generic words
    words = extract_meaningful_words(text)
    if not words:
        return ""

    # Frequency scoring
    freq = Counter(words)
    total = sum(freq.values())
    freq_scores = {w: freq[w] / total for w in freq}

    # Semantic scoring (KeyBERT)
    candidates = kw_model.extract_keywords(
        text,
        keyphrase_ngram_range=(1, 1),
        stop_words="english",
        top_n=6
    )

    # Combine semantic + frequency, picking the best
    best_word = None
    best_score = -1.0
    for word, sem_score in candidates:
        w = word.lower().strip()
        if w in GENERIC_STOPWORDS or w in AUTH_WORDS:
            continue
        freq_score = freq_scores.get(w, 0.0)
        final = 0.7 * sem_score + 0.3 * freq_score
        if final > best_score:
            best_score = final
            best_word = w

    # fallback to most frequent meaningful word
    chosen = best_word if best_word else freq.most_common(1)[0][0]
    return normalize(chosen)