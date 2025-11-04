import requests
import re

# Google Custom Search API details
API_KEY = "AIzaSyAjOAtRNNedpyov7F6B0XDCiaK46wjT7Ks"   # Replace with your Google Cloud key
CSE_ID = "012899561505164599335:tb0er0xsk_o"  # MITRE CWE Search Engine

def search_cwe(keyword: str):
    """
    Search CWE entries using Google's Custom Search API (MITRE CSE).
    Supports:
      - normal: returns the best (first) CWE ID
      - -aggressive <keyword>: returns top 5 CWE IDs
      - -extreme <keyword>: returns all found CWE IDs
    """
    # Mode detection
    mode = "normal"
    if keyword.startswith("-aggressive "):
        mode = "aggressive"
        keyword = keyword[len("-aggressive "):].strip()
    elif keyword.startswith("-extreme "):
        mode = "extreme"
        keyword = keyword[len("-extreme "):].strip()

    # API endpoint
    url = "https://www.googleapis.com/customsearch/v1"

    params = {
        "key": API_KEY,
        "cx": CSE_ID,
        "q": keyword,
        "num": 10,  # max per request (can paginate if needed)
        "safe": "off",
        "fields": "items(link,title,snippet)"
    }

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        print(f"[!] API request failed: {e}")
        return None

    items = data.get("items", [])
    if not items:
        print("[!] No results found.")
        return None

    # Extract CWE IDs from URLs
    cwe_ids = []
    for item in items:
        link = item.get("link", "")
        match = re.search(r"/data/definitions/(\d+)\.html", link)
        if match:
            cwe_ids.append(f"CWE-{match.group(1)}")

    if not cwe_ids:
        print("[!] No valid CWE IDs found in results.")
        return None

    # Limit output based on mode
    if mode == "normal":
        return cwe_ids[0]
    elif mode == "aggressive":
        return cwe_ids[:5]
    else:  # extreme
        return cwe_ids
