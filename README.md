# VEACOR
## Vulnerability & Exploit Automated Correlation and Ontology Roadmap Framework

VEACOR is a professional cybersecurity framework designed to automatically generate structured attack graphs from a single input entity.  
It correlates data across major MITRE and NVD knowledge bases, linking vulnerabilities, weaknesses, attack patterns, adversarial techniques, and defensive controls into a unified, multi-layer roadmap.

The framework is intended for:

- Penetration testers  
- Red team operators  
- Threat intelligence analysts  
- Security researchers  
- Defensive architects  

---

# 1. Overview

VEACOR enables automated correlation across:

- CPE (Common Platform Enumeration)
- CVE (Common Vulnerabilities and Exposures)
- CWE (Common Weakness Enumeration)
- CAPEC (Common Attack Pattern Enumeration and Classification)
- MITRE ATT&CK
- MITRE D3FEND

Relationship chains such as:

CPE → CVE → CWE → CAPEC → ATT&CK → D3FEND

are generated automatically using:

- Official structured mappings (MITRE / NVD)
- NLP-based semantic similarity inference

The output consists of structured JSON data and an interactive attack graph.

---

# 2. Key Capabilities

- Automated cross-framework intelligence correlation
- Hybrid structured + semantic linking
- Multi-layer attack path construction
- Offensive-to-defensive knowledge bridging
- Configurable expansion depth
- Interactive drill-down visualization
- Reproducible roadmap generation from minimal input

---

# 3. Architecture

veacor/
- cli.py                         — Command-line interface
- roadmap_builder.py             — Graph expansion engine
- Visualize.py                   — Dash-based visualization
- Retrieves/
    - CPE_retrieve.py
    - CVE_retrieve.py
    - CWE_retrieve.py
    - CAPEC_retrieve.py
    - ATTACKDEFEND_retrieve.py
    - NLP_relationship_finder.py
    - text_cleaning.py

---

# 4. Installation (Automated Installers)

VEACOR provides cross-platform installers that automatically:

- Create a virtual environment (.venv)
- Upgrade pip, setuptools, wheel
- Install dependencies from requirements.txt
- Install VEACOR locally (editable mode)
- Register the `veacorg` CLI command
- Validate installation via `veacorg --help`

Available installers:

Windows:
- VEACOR_WIN_installer.bat

Linux:
- VEACOR_LINUX_installer.desktop

macOS:
- VEACOR_macOS_installer.command

Primary Python installer:
- VEACOR_installer.py

## Windows

Run:
VEACOR_WIN_installer.bat

## Linux

chmod +x VEACOR_LINUX_installer.desktop  
Then execute or double-click it.

## macOS

chmod +x VEACOR_macOS_installer.command  
Then run:
./VEACOR_macOS_installer.command

## Manual (Advanced)

python VEACOR_installer.py

After installation:

veacorg --help

---

# 5. Usage

veacorg <INPUT>

Supported inputs:

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

CPE:
veacorg cpe:2.3:a:apache:http_server:2.4.49

Product search:
veacorg -p "Microsoft IIS 3.0"

Description resolution:
veacorg -desc CWE

---

# 6. Expansion Modes

--mode default   (TOP_K = 5)  
--mode agg       (TOP_K = 20)  
--mode xtrm      (Unlimited)

Example:
veacorg CVE-2023-4412 --mode agg

---

# 7. Output Structure

outputs/
└── roadmap_<INPUT>_output/
    ├── roadmap_<INPUT>.json
    ├── CPEs.json
    ├── CVEs.json
    ├── CWEs.json
    ├── CAPECs.json
    ├── ATTACKs.json
    └── DEFENDs.json

---

# 8. Visualization

Interactive Dash-based attack graph with:

- Entity-type grouping
- Metadata side panel
- Double-click JSON drill-down
- Neighbor highlighting
- Deterministic layout

---

# 9. NLP Correlation Engine

Hybrid similarity model using:

- SentenceTransformer embeddings
- Keyword overlap scoring
- Title similarity
- Length normalization scaling

Default:

EMBED_MODEL_NAME = sentence-transformers/multi-qa-mpnet-base-dot-v1  
MIN_SCORE = 0.85  
TOP_K = 5  

---

# 10. Operational Use Cases

- Vulnerability chaining
- Red team scenario planning
- Defensive control mapping
- Threat modeling
- Security reporting

---

# 11. Limitations

- Internet required
- NLP links are probabilistic
- Extreme expansion may increase graph size

---

# 12. Research Context

Developed as part of a diploma thesis on automated attack graph generation.

---

# 13. License

Academic and research use.  
For commercial use, contact the author.
