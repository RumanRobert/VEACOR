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

# VEACOR

## Installation and Setup

The tool can be downloaded from the VEACOR GitHub repository. Click the **"Download ZIP"** button on the repository page, then extract the contents. Installation is done by running the appropriate installer for your operating system (see sections below).

> **Fallback:** If you encounter compatibility issues or errors with the installer scripts, you can run `VEACOR_installer.py` directly from the console.

Running the setup script installs all necessary libraries and makes the tool immediately available. Upon successful installation, your system's console will automatically open and display the VEACOR logo followed by the output of the `--help` command — this confirms the installation completed successfully.

---

### Windows

1. After extracting the ZIP, navigate to `VEACOR-main → Installers`.
2. Double-click **`VEACOR_WIN_installer.bat`** to run the installer.
3. If a Windows security popup appears, click **"Run anyway"** to allow the installation to proceed.
4. Once complete, the Windows console will open automatically and display the tool logo and usage information.

---

### macOS

1. After extracting the archive, open **Terminal**.
2. Run the following command (adjust the path if you extracted to a different location):

```
bash ~/Downloads/VEACOR-main/Installers/VEACOR_macOS_installer.command
```

3. Once the command completes, the Terminal will display usage examples confirming the virtual environment is ready.

> **macOS Gatekeeper:** macOS may block the installer since it is not signed through Apple's developer programme. If prompted, go to **System Settings → Privacy & Security** and explicitly grant permission to run the installer.

#### Activating the virtual environment

On macOS, VEACOR is only accessible within the virtual environment created during installation. **Each time you open a new Terminal session**, you must activate it before using the tool:

```
cd ~/Downloads/VEACOR-main
source .venv/bin/activate
```

The `veacor` command will only be available after this activation step.

---

### Linux

1. After extracting the files, navigate to the `Installers` folder.
2. Right-click **`VEACOR_LINUX_installer.sh`** and select **"Run as program"**.
3. Once complete, the tool's help output will be displayed automatically, confirming successful installation.

> **Fallback:** You can also install by running `VEACOR_installer.py` directly with Python. Note that VEACOR currently supports **Python 3.9, 3.10, 3.11, and 3.12** only.

---

## Performance Reference

Run-time is influenced by the number and complexity of nodes in the input. The table below shows example run-times for each supported input type:

| Input       | Number of nodes | Run-time (s) |
|-------------|-----------------|--------------|
| CVE-2025-8452 | 73            | 248.9        |
| CWE-778       | 64            | 224.4        |
| CAPEC-63      | 120           | 345.0        |
| T1195         | 37            | 184.7        |
| D3-AMED       | 137           | 300.4        |
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
