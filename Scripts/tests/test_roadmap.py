import sys, os, pytest
# --- Ensure we can import the project modules ---
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "Retrieves"))
import NLP_relationship_finder as nlpmod
from main import (
    build_roadmap,
    handle_attack_input,
    detect_type,
    ensure_list,
    is_keyword_or_text,
)
from NLP_relationship_finder import link_nodes, min_max_scale, normalize_ws
from LLM import extract_keyword


# ============================================================
# === BASIC UTILITIES & DETECTION TESTS ======================
# ============================================================

def test_detect_type_all():
    assert detect_type("CVE-2021-44228") == "CVE"
    assert detect_type("CWE-79") == "CWE"
    assert detect_type("CAPEC-100") == "CAPEC"
    assert detect_type("T1059.001") == "ATTACK"
    assert detect_type("D3-DEFEND") == "DEFEND"
    assert detect_type("NVD-CWE-79") == "CWE"
    assert detect_type("random") == "UNKNOWN"


def test_is_keyword_or_text():
    assert is_keyword_or_text("CVE-2021-9999") == "id"
    assert is_keyword_or_text("sql injection") == "text"
    assert is_keyword_or_text("buffer") == "keyword"


def test_ensure_list_variants():
    assert ensure_list(None) == []
    assert ensure_list("x") == ["x"]
    assert ensure_list({"a": 1}) == [{"a": 1}]
    assert ensure_list(["a", "b"]) == ["a", "b"]
    assert set(ensure_list({"a", "b"})) == {"a", "b"}


# ============================================================
# === NLP HELPER TESTS =======================================
# ============================================================

def test_min_max_scale_and_normalize_ws():
    import numpy as np
    arr = np.array([1, 2, 3])
    scaled = min_max_scale(arr)
    assert scaled[0] == 0 and scaled[-1] == 1
    assert all(0 <= x <= 1 for x in scaled)
    assert normalize_ws("  hello   world  ") == "hello world"


def test_link_nodes_basic(monkeypatch):
    """Ensure link_nodes returns a list of CAPEC mappings."""
    import NLP_relationship_finder as nlpmod

    # ✅ Mock HybridMatcher to avoid SentenceTransformer initialization
    class MockMatcher:
        def __init__(self, *a, **kw):
            self.current_target_key = "CAPEC"

        def expand_synonyms(text):
            return text  # just return the input text unchanged

        def rank(self, source_description, target_set, **kw):
            return [({"CAPEC_ID": "CAPEC-100"}, 0.95, 0.9, 0.8)]

    # ✅ Monkeypatch only what's needed
    monkeypatch.setattr(nlpmod, "HybridMatcher", MockMatcher)
    monkeypatch.setattr(nlpmod, "fetch_cwe_entries", lambda limit=None: [{"CWE_ID": "CWE-1"}])

    result = nlpmod.link_nodes("example text", "CAPEC")
    assert isinstance(result, list)
    assert result[0][0]["CAPEC_ID"] == "CAPEC-100"



# ============================================================
# === LLM MOCK TEST ==========================================
# ============================================================

def test_extract_keyword(monkeypatch):
    """Test keyword extraction using a mocked KeyBERT model."""

    def mock_extract_keywords(text, **kwargs):
        return [("mocked", 0.95), ("keyword", 0.9)]

    # ✅ Mock NLP to produce one token with lemma_="logging"
    class MockToken:
        def __init__(self, lemma):
            self.lemma_ = lemma

    class MockDoc(list):
        def __init__(self, tokens):
            super().__init__(tokens)

    monkeypatch.setattr("LLM.kw_model.extract_keywords", mock_extract_keywords)
    monkeypatch.setattr("LLM.nlp", lambda text: MockDoc([MockToken("logging")]))

    result = extract_keyword("Some description about logging failures")
    assert isinstance(result, str)
    assert result.lower() == "logging"

# ============================================================
# === MAIN BUILD PATH TESTS ==================================
# ============================================================

def test_build_roadmap_cve(monkeypatch):
    from Scripts.Retrieves import main
    monkeypatch.setattr(main, "fetch_cve_data", lambda cve_id: {"CVE_ID": cve_id, "Related_CWEs": ["CWE-79"]})
    monkeypatch.setattr(main, "fetch_cwe_data", lambda cwe_id: {"CWE_ID": cwe_id, "Related_CAPEC": ["CAPEC-100"]})
    monkeypatch.setattr(main, "fetch_capec_data", lambda capec_id: {"CAPEC_ID": capec_id, "Related_MITRE_ATT&CK": ["T1059.001"]})
    monkeypatch.setattr(main, "fetch_attack_data", lambda attack_id: {"ATTACK": attack_id, "DEFEND": ["D3-Example"]})
    monkeypatch.setattr(main, "fetch_defend_data", lambda d3_id: {"DEFEND": d3_id})

    result = build_roadmap("CVE-2025-9999")
    assert result["Detected_Type"] == "CVE"
    assert all(k in result["Nodes"] for k in ["CVE", "CWE", "CAPEC", "ATTACK", "DEFEND"])


def test_build_roadmap_cwe(monkeypatch):
    from Scripts.Retrieves import main
    monkeypatch.setattr(main, "fetch_cwe_data", lambda cwe_id: {"CWE_ID": cwe_id, "Related_CAPEC": ["CAPEC-100"]})
    monkeypatch.setattr(main, "fetch_cve_data", lambda cve_id: {"CVE_ID": cve_id})
    monkeypatch.setattr(main, "fetch_capec_data", lambda capec_id: {"CAPEC_ID": capec_id, "Related_MITRE_ATT&CK": ["T1001"]})
    monkeypatch.setattr(main, "fetch_attack_data", lambda attack_id: {"ATTACK": attack_id, "DEFEND": ["D3-Test"]})
    monkeypatch.setattr(main, "fetch_defend_data", lambda d3_id: {"DEFEND": d3_id})

    result = build_roadmap("CWE-79")
    assert result["Detected_Type"] == "CWE"
    assert "CWE" in result["Nodes"]
    assert "CAPEC" in result["Nodes"]


def test_build_roadmap_capec(monkeypatch):
    from Scripts.Retrieves import main
    monkeypatch.setattr(main, "fetch_capec_data", lambda capec_id: {"CAPEC_ID": capec_id, "Related_MITRE_ATT&CK": ["T1234"], "Related_CWEs": ["CWE-1"]})
    monkeypatch.setattr(main, "fetch_attack_data", lambda attack_id: {"ATTACK": attack_id, "DEFEND": ["D3-Example"]})
    monkeypatch.setattr(main, "fetch_defend_data", lambda d3_id: {"DEFEND": d3_id})
    monkeypatch.setattr(main, "fetch_cwe_data", lambda cwe_id: {"CWE_ID": cwe_id, "Related_CVEs": ["CVE-1"]})
    monkeypatch.setattr(main, "fetch_cve_data", lambda cve_id: {"CVE_ID": cve_id})

    result = build_roadmap("CAPEC-100")
    assert result["Detected_Type"] == "CAPEC"
    assert "ATTACK" in result["Nodes"]
    assert "DEFEND" in result["Nodes"]


def test_build_roadmap_attack(monkeypatch):
    from Scripts.Retrieves import main
    monkeypatch.setattr(main, "fetch_attack_data", lambda attack_id: {"ATTACK": attack_id, "DEFEND": ["D3-Mock"], "Description": "desc"})
    monkeypatch.setattr(main, "fetch_defend_data", lambda d3_id: {"DEFEND": d3_id})
    monkeypatch.setattr(main, "link_nodes", lambda desc, t, **kw: [({"CAPEC_ID": "CAPEC-123"}, 0.9, 0.8, 0.7)])
    monkeypatch.setattr(main, "fetch_capec_data", lambda capec_id: {"CAPEC_ID": capec_id})
    monkeypatch.setattr(main, "fetch_cwe_data", lambda cwe_id: {"CWE_ID": cwe_id})

    result = build_roadmap("T1059.001")
    assert result["Detected_Type"] == "ATTACK"
    assert "ATTACK" in result["Nodes"]
    assert "DEFEND" in result["Nodes"]


def test_build_roadmap_defend(monkeypatch):
    from Scripts.Retrieves import main
    monkeypatch.setattr(main, "fetch_defend_data", lambda d3_id: {"DEFEND": d3_id, "RELATED_ATTACKS": ["T1001"]})
    monkeypatch.setattr(main, "fetch_attack_data", lambda attack_id: {"ATTACK": attack_id, "Description": "mock"})
    result = build_roadmap("D3-DEFEND")
    assert result["Detected_Type"] == "DEFEND"
    assert "DEFEND" in result["Nodes"]
    assert "ATTACK" in result["Nodes"]


def test_build_roadmap_attack_capec_failure(monkeypatch):
    from Scripts.Retrieves import main
    monkeypatch.setattr(main, "fetch_attack_data", lambda attack_id: {"ATTACK": attack_id, "DEFEND": []})
    monkeypatch.setattr(main, "fetch_defend_data", lambda d3_id: {"DEFEND": d3_id})
    monkeypatch.setattr(main, "link_nodes", lambda *a, **kw: (_ for _ in ()).throw(Exception("mock failure")))

    result = build_roadmap("T1001")
    assert any("CAPEC" in note or "failed" in note.lower() for note in result["Notes"])


def test_handle_attack_input(monkeypatch):
    from Scripts.Retrieves import main
    monkeypatch.setattr(main, "fetch_attack_data", lambda attack_id: {"ATTACK": attack_id, "DEFEND": ["D3-1"], "Description": "mock"})
    monkeypatch.setattr(main, "fetch_defend_data", lambda d3_id: {"DEFEND": d3_id, "RELATED_ATTACKS": []})
    monkeypatch.setattr(main, "link_nodes", lambda desc, t, **kw: ["CAPEC-1"])
    monkeypatch.setattr(main, "build_recursive", lambda *a, **kw: None)

    result = handle_attack_input("T1234")
    assert result["Detected_Type"] == "ATTACK"
    assert "DEFEND" in result["Nodes"]
    assert "ATTACK" in result["Nodes"]
    assert isinstance(result["Nodes"]["DEFEND"], list)


# ============================================================
# === EDGE CASES =============================================
# ============================================================

def test_build_roadmap_unknown_id():
    from Scripts.Retrieves import main
    result = main.build_roadmap("unknownthing")
    assert result["Detected_Type"] == "UNKNOWN"
    assert isinstance(result["Nodes"], dict)
