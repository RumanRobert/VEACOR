# VEACOR
## Vulnerability & Exploit Automated Correlation and Ontology Roadmap Framework

VEACOR is a professional cybersecurity framework designed to automatically generate structured attack graphs from a single input entity.  
It correlates data across major MITRE and NVD knowledge bases, linking vulnerabilities, weaknesses, attack patterns, adversarial techniques, and defensive controls into a unified, multi-layer roadmap.

The framework is intended for:

- Penetration testers  
- Red team operators  
- Threat intelligence analysts  
- Security researchers  
- Blue team and defensive architects  

---

# 1. Overview

VEACOR enables automated correlation across the following ecosystems:

- CPE (Common Platform Enumeration)
- CVE (Common Vulnerabilities and Exposures)
- CWE (Common Weakness Enumeration)
- CAPEC (Common Attack Pattern Enumeration and Classification)
- MITRE ATT&CK
- MITRE D3FEND

The system constructs relationship chains such as:

CPE → CVE → CWE → CAPEC → ATT&CK → D3FEND

Relationships are derived using:

- Official structured mappings (MITRE / NVD references)
- NLP-based semantic similarity inference

The output is a structured JSON attack graph and an interactive visualization.

---

# 2. Key Capabilities

- Automated cross-framework intelligence correlation
- Hybrid structured + semantic linking
- Multi-layer attack path generation
- Offensive-to-defensive knowledge mapping
- Configurable graph expansion modes
- Interactive visualization with node-level drill-down
- Reproducible roadmap generation from minimal input

---

# 3. Architecture

## Core Components

veacor/
- cli.py                         — Command-line entry point
- roadmap_builder.py             — Graph orchestration and expansion engine
- Visualize.py                   — Interactive Dash visualization
- Retrieves/
    - CPE_retrieve.py
    - CVE_retrieve.py
    - CWE_retrieve.py
    - CAPEC_retrieve.py
    - ATTACKDEFEND_retrieve.py
    - NLP_relationship_finder.py
    - text_cleaning.py

### Processing Flow

1. User provides a single identifier or product keyword.
2. Data is retrieved from authoritative sources.
3. Structured relationships are extracted.
4. NLP similarity is applied for cross-dataset inference.
5. Multi-layer roadmap is constructed.
6. Structured JSON files are generated.
7. Interactive visualization is launched.

---

# 4. Installation

## Requirements

- Python 3.10+
- Internet connection (for data retrieval and model download)

## Setup

Create and activate a virtual environment:

Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate

Windows:
python -m venv .venv
.\.venv\Scripts\activate

Install dependencies:

pip install requests beautifulsoup4 sentence-transformers scikit-learn torch nltk dash dash-cytoscape networkx numpy

---

# 5. Usage

VEACOR is executed via CLI:

veacorg <INPUT>

## Supported Inputs

CVE:
veacorg CVE-2023-4412

CWE:
veacorg CWE-78

CAPEC:
veacorg CAPEC-100

MITRE ATT&CK:
veacorg T1059

MITRE D3FEND:
veacorg D3-DAE

CPE 2.3:
veacorg cpe:2.3:a:apache:http_server:2.4.49

Product keyword search:
veacorg -p "Microsoft IIS 3.0"

Description-based resolution:
veacorg -desc CWE

---

# 6. Expansion Modes

Graph expansion size can be controlled using:

--mode default   (TOP_K = 5)  
--mode agg       (TOP_K = 20)  
--mode xtrm      (Unlimited expansion)

Example:

veacorg CVE-2023-4412 --mode agg

---

# 7. Output Structure

Each execution generates:

outputs/
└── roadmap_<INPUT>_output/
    ├── roadmap_<INPUT>.json
    ├── CPEs.json
    ├── CVEs.json
    ├── CWEs.json
    ├── CAPECs.json
    ├── ATTACKs.json
    └── DEFENDs.json

The unified roadmap JSON contains:

- Nodes
- Edges
- Relationship types (Structured / NLP Link)
- File references to detailed entity data

---

# 8. Visualization

VEACOR includes a Dash-based interactive network interface.

Features:

- Entity-type color grouping
- Node metadata side panel
- Double-click to open detailed JSON record
- Neighbor highlighting for local analysis
- Deterministic layout for reproducibility

---

# 9. NLP Correlation Engine

The semantic linking engine combines:

- SentenceTransformer embeddings (multi-qa-mpnet-base-dot-v1)
- Keyword overlap scoring (Jaccard similarity)
- Title similarity scoring
- Length normalization scaling

Default configuration:

EMBED_MODEL_NAME = sentence-transformers/multi-qa-mpnet-base-dot-v1  
MIN_SCORE = 0.85  
TOP_K = 5  

Caching is implemented for:

- Dataset embeddings
- Preprocessed descriptions
- Previously computed similarity queries

---

# 10. Practical Applications

VEACOR can support:

- Attack surface analysis
- Vulnerability chaining research
- Red team scenario construction
- Defensive control mapping
- Threat modeling exercises
- Security research and reporting

---

# 11. Limitations

- Requires internet connectivity during execution
- NLP-based links are probabilistic, not authoritative mappings
- Extreme expansion mode may generate large graphs
- Performance depends on dataset size and threshold configuration

---

# 12. Research Context

This framework was developed as part of a diploma thesis on automated attack graph generation.  
It demonstrates how structured CTI and semantic similarity modeling can be combined to automate multi-layer adversarial roadmap construction.

---

# 13. License

Academic and research use.  
For commercial use or redistribution, consult the project author.
