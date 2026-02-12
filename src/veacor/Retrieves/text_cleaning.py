# attack2vul/text_cleaning.py
import re

_CITATION = r'\(Citation:.*?\)'
_URL = r'http[s]?://(?:[a-zA-Z0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F]{2}))+'

def remove_citations_and_urls(text: str) -> str:
    text = re.sub(_CITATION, '', text)
    text = re.sub(_URL, '', text)
    text = re.sub("^<code>.*</code>$", "", text, flags=re.MULTILINE)
    text = " ".join(text.split())
    text = re.sub("[^A-Za-z0-9]", " ", text)
    return text

def clean_attack_description(s: str) -> str:
    s = re.sub(r'^[\[\]"\s]+|[\[\]"\s]+$', '', str(s))
    s = s.replace("\\xa0\\n\\n", "").replace("\n", " ").replace("\\n", " ").replace("\\xa0", " ")
    s = re.sub(r'\s+', ' ', s).strip()
    return remove_citations_and_urls(s)

def bulk_clean(texts):
    return [remove_citations_and_urls(str(t)) for t in texts]


# attack2vul/text_cleaning.py

# import re
#
# # -------------------------------------------------------------------
# # Patterns to remove (noise only)
# # -------------------------------------------------------------------
# _CITATION = r'\(Citation:.*?\)'  # Keep this – safe to remove
# _URL = r'https?://\S+|www\.\S+'  # URLs are noise
#
# # Professional CTI-safe cleaning function
# def remove_citations_and_urls(text: str) -> str:
#     """
#     Removes:
#       - URLs
#       - Inline MITRE citation blocks
#       - HTML/XML tags
#     Preserves:
#       - Cyber domain vocabulary (metadata, exploit kit, EXIF, etc.)
#       - Punctuation that SBERT uses for context
#       - MITRE tactic/phase keywords
#     """
#
#     if not text:
#         return ""
#
#     # Remove citations like (Citation: X):
#     text = re.sub(_CITATION, '', text, flags=re.IGNORECASE)
#
#     # Remove URLs:
#     text = re.sub(_URL, '', text, flags=re.IGNORECASE)
#
#     # Remove HTML/XML tags but keep content:
#     text = re.sub(r'<[^>]+>', ' ', text)
#
#     # Normalize whitespace:
#     text = re.sub(r'\s+', ' ', text).strip()
#
#     return text
#
#
# def clean_attack_description(s: str) -> str:
#     """
#     Cleans ATT&CK technique descriptions safely:
#       - Trim outer quotes/brackets
#       - Normalize whitespace
#       - Remove URLs/citations
#       - Preserve cyber-domain nouns, verbs, terminology
#     """
#     if not s:
#         return ""
#
#     # Remove stray formatting characters (but not domain words)
#     s = re.sub(r'^[\[\]"\s]+|[\[\]"\s]+$', '', str(s))
#
#     # Normalize escaped whitespace:
#     s = (
#         s.replace("\\xa0\\n\\n", " ")
#          .replace("\\xa0", " ")
#          .replace("\\n", " ")
#          .replace("\n", " ")
#     )
#
#     # Collapse whitespace:
#     s = re.sub(r'\s+', ' ', s).strip()
#
#     # Perform safe domain-aware cleaning:
#     return remove_citations_and_urls(s)
#
#
# def bulk_clean(texts):
#     return [remove_citations_and_urls(str(t)) for t in texts]
