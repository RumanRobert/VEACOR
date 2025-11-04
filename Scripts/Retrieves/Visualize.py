'''
#ORIGINAL DISPLAY

# ------------------------------------------------------
# Select JSON file interactively (recursive + grouped display)
# ------------------------------------------------------
import os
import json
import textwrap
import re
import plotly.graph_objects as go

def find_json_files_grouped(base_dir="."):
    """
    Recursively find all .json files grouped by their immediate parent folder.
    Returns: {folder_name: [full_paths]}
    """
    grouped = {}
    for root, _, files in os.walk(base_dir):
        jsons = [os.path.join(root, f) for f in files if f.lower().endswith(".json")]
        if jsons:
            folder_name = os.path.relpath(root, base_dir)
            grouped.setdefault(folder_name, []).extend(sorted(jsons))
    return grouped


# Gather all JSONs grouped by folder
grouped_jsons = find_json_files_grouped(".")

if not grouped_jsons:
    print("❌ No JSON files found in this directory or subdirectories.")
    exit(1)

# Flatten grouped list with numbering for easy selection
json_files = []
print("\n📁 Available JSON files (grouped by folder):\n" + "-" * 70)
counter = 1
folder_file_map = {}

for folder, files in grouped_jsons.items():
    print(f"\n{folder}:")
    for f in files:
        display_name = os.path.basename(f)
        print(f"   {counter}. {display_name}")
        json_files.append(f)
        folder_file_map[counter] = f
        counter += 1

print("-" * 70)

# === Prompt user selection ===
while True:
    choice = input("Enter the number of the JSON file to visualize (or 'q' to quit): ").strip()
    if choice.lower() == "q":
        print("👋 Exiting visualizer.")
        sys.exit(0)

    if not choice.isdigit() or int(choice) not in folder_file_map:
        print("⚠️ Invalid choice. Please select a valid number.")
        continue

    filename = folder_file_map[int(choice)]
    print(f"\n📂 Using file: {filename}\n")

    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)

    break  # proceed with visualization

if not json_files:
    print("❌ No JSON files found in this directory or subdirectories.")
    exit(1)

while True:
    print("\nAvailable JSON files (including subfolders):\n" + "-" * 60)
    for i, f in enumerate(json_files, 1):
        display_name = os.path.relpath(f, ".")
        print(f"{i}. {display_name}")
    print("-" * 60)

    choice = input("Enter the number of the JSON file to visualize (or 'q' to quit): ").strip()
    if choice.lower() == "q":
        print("👋 Exiting visualizer.")
        break

    if not choice.isdigit() or not (1 <= int(choice) <= len(json_files)):
        print("⚠️ Invalid choice. Try again.")
        continue

    filename = json_files[int(choice) - 1]
    print(f"\n📂 Using file: {filename}\n")

    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Continue with the rest of your visualization logic below...


    # ⬇️ everything below (root detection, building graph, plotting, etc.)
    # stays exactly as it is

    # ------------------------------------------------------
    # Root detection from filename
    # ------------------------------------------------------
    def detect_root_from_filename(name: str):
        base = os.path.basename(name)
        stem = os.path.splitext(base)[0]  # "roadmap_CVE-2025-9975"
        # Expect "roadmap_<ID>"
        m = re.match(r"^roadmap_(.+)$", stem, flags=re.IGNORECASE)
        if not m:
            return None, None
        root_id = m.group(1)

        # Decide type from prefix
        if root_id.upper().startswith("CVE-"):
            return "CVE", root_id.upper()
        if root_id.upper().startswith("CWE-"):
            return "CWE", root_id.upper()
        if root_id.upper().startswith("CAPEC-"):
            return "CAPEC", root_id.upper()
        if root_id.upper().startswith("T"):
            return "ATTACK", root_id  # keep case for Txxxx
        if root_id.upper().startswith("D3-"):
            return "DEFEND", root_id.upper()
        return None, root_id

    root_type, root_id = detect_root_from_filename(filename)
    if not root_type:
        print("⚠️ Could not determine root type from filename — defaulting to CVE.")
        root_type = "CVE"

    print(f"🔍 Root determined from filename: type={root_type}, id={root_id}")

    # ------------------------------------------------------
    # Init helpers and structures
    # ------------------------------------------------------
    nodes = []
    links = []
    node_info = {}

    def get_index(name):
        if name not in nodes:
            nodes.append(name)
        return nodes.index(name)

    def add_link(src, dst):
        if src and dst and (src, dst) not in links:
            links.append((src, dst))

    def safe_field(value):
        return str(value).strip() if value else "None"

    def wrap_text(text, width=80):
        if not text or text == "None":
            return "None"
        return "<br>".join(textwrap.wrap(text, width))

    def ensure_list(x):
        if x is None:
            return []
        if isinstance(x, list):
            return x
        if isinstance(x, set):
            return list(x)
        if isinstance(x, dict):
            return [x]
        return [x]

    # ------------------------------------------------------
    # Seed the root (for CVE-rooted we want only the single CVE visible later)
    # ------------------------------------------------------
    root_cve = None
    if root_type == "CVE" and data["Nodes"].get("CVE"):
        # Prefer the CVE from the filename if it matches; otherwise first CVE entry
        file_cve = root_id if (root_id and root_id.startswith("CVE-")) else None
        if file_cve:
            root_cve = file_cve
        else:
            root_cve = data["Nodes"]["CVE"][0].get("CVE_ID", "")

        if root_cve:
            if root_cve not in nodes:
                nodes.append(root_cve)
            # Try to pull metadata from Nodes.CVE if present
            cve_meta = next((x for x in data["Nodes"].get("CVE", []) if x.get("CVE_ID") == root_cve), None)
            node_info[root_cve] = {
                "Title": (cve_meta or {}).get("Title", ""),
                "Description": (cve_meta or {}).get("Description", ""),
                "Source": (cve_meta or {}).get("Source_Page", (cve_meta or {}).get("Source_API", "")),
                "CVSS_Score": (cve_meta or {}).get("CVSS_Score", (cve_meta or {}).get("CVSS", "")),
            }

    # ------------------------------------------------------
    # Build directional relationships (with ancestry chain)
    # ------------------------------------------------------
    for cwe in data["Nodes"].get("CWE", []):
        cwe_id = cwe.get("CWE_ID", "")
        parent_cwe = cwe.get("Parent_CWE", None)

        # CVE → CWE
        if root_type == "CVE" and root_cve:
            add_link(root_cve, cwe_id)
        else:
            related_cves = ensure_list(cwe.get("Related_CVEs", []))
            if max_cves_per_cwe:
                related_cves = related_cves[:max_cves_per_cwe]  # cap the list

            for cve in related_cves:
                add_link(cve, cwe_id)
                if cve not in nodes:
                    nodes.append(cve)
                if cve not in node_info:
                    node_info[cve] = {
                        "Title": "CVE record (not expanded)",
                        "Description": "Metadata not retrieved — shown for relationship context only.",
                        "Source": f"https://nvd.nist.gov/vuln/detail/{cve}.hmtl",
                    }

        # CWE → CAPEC (direct)
        for capec in ensure_list(cwe.get("Related_CAPEC", [])):
            add_link(cwe_id, capec)

        # Inherited CAPECs (for compatibility if ancestry_chain missing)
        inherited = cwe.get("Inherited_CAPEC", {})
        if inherited and isinstance(inherited, dict) and not ancestry_chain:
            parent = inherited.get("From")
            capecs = ensure_list(inherited.get("CAPECs", []))
            if parent:
                if not parent.startswith("CWE-"):
                    parent = f"CWE-{parent}"
                for capec in capecs:
                    add_link(parent, capec)
                inherited_nodes.add(parent)
                for capec in capecs:
                    inherited_nodes.add(capec)

    # CAPEC → ATTACK (filtered for ATTACK-rooted graphs)
    for capec in data["Nodes"].get("CAPEC", []):
        capec_id = capec.get("CAPEC_ID", "")
        related_attacks = ensure_list(capec.get("Related_MITRE_ATT&CK", []))

        # Only keep CAPECs linked to our root attack if the graph is ATTACK-rooted
        if root_type == "ATTACK":
            if not related_attacks or root_id not in related_attacks:
                continue  # skip CAPECs not linked to the root ATTACK

        for attack in related_attacks:
            add_link(capec_id, attack)

    # ATTACK → DEFEND (filtered for ATTACK-rooted graphs)
    for attack in data["Nodes"].get("ATTACK", []):
        attack_id = attack.get("ATTACK", "")
        if root_type == "ATTACK" and attack_id != root_id:
            continue  # skip unrelated ATTACKs
        for defend in set(ensure_list(attack.get("DEFEND", []))):
            add_link(attack_id, defend)

    # ------------------------------------------------------
    # Ensure CVE nodes & metadata are registered (from Nodes.CVE)
    # ------------------------------------------------------
    for cve_obj in data["Nodes"].get("CVE", []):
        cid = cve_obj.get("CVE_ID")
        if not cid:
            continue
        if cid not in nodes:
            nodes.append(cid)
        node_info.setdefault(cid, {})
        node_info[cid].setdefault("Title", cve_obj.get("Title", ""))
        node_info[cid].setdefault("Description", cve_obj.get("Description", ""))
        node_info[cid].setdefault("Source", cve_obj.get("Source_Page", cve_obj.get("Source_API", "")))
        cvss = cve_obj.get("CVSS_Score") or cve_obj.get("CVSS")
        if cvss:
            node_info[cid].setdefault("CVSS_Score", cvss)

    # ------------------------------------------------------
    # Compute connected nodes from all link pairs
    # ------------------------------------------------------
    connected_nodes = sorted(set([n for l in links for n in l]))

    # Additional pruning for ATTACK-rooted graphs
    if root_type == "ATTACK" and root_id:
        # Find CAPECs actually connected to this ATTACK
        valid_capecs = []
        for capec in data["Nodes"].get("CAPEC", []):
            related_attacks = ensure_list(capec.get("Related_MITRE_ATT&CK", []))
            if root_id in related_attacks:
                valid_capecs.append(capec.get("CAPEC_ID"))

        # Keep only CAPECs directly linked to root ATTACK
        connected_nodes = [n for n in connected_nodes if not n.startswith("CAPEC-") or n in valid_capecs]

        # Remove ATTACK nodes that are not the root
        connected_nodes = [n for n in connected_nodes if not (n.startswith("T") and n != root_id)]

    # Additional pruning for ATTACK-rooted graphs
    if root_type == "ATTACK" and root_id:
        # Find CAPECs actually connected to this ATTACK
        valid_capecs = []
        for capec in data["Nodes"].get("CAPEC", []):
            related_attacks = ensure_list(capec.get("Related_MITRE_ATT&CK", []))
            if root_id in related_attacks:
                valid_capecs.append(capec.get("CAPEC_ID"))

        # Keep only CAPECs directly linked to root ATTACK
        connected_nodes = [n for n in connected_nodes if not n.startswith("CAPEC-") or n in valid_capecs]

    # Additional pruning for DEFEND-rooted graphs
    if root_type == "DEFEND" and root_id:
        # Build reverse adjacency: target -> {sources}
        rev_adj = {}
        for s, t in links:
            rev_adj.setdefault(t, set()).add(s)

        # Walk backwards from the DEFEND root to collect all ancestors on any path
        keep = set()
        stack = [root_id]
        while stack:
            cur = stack.pop()
            if cur in keep:
                continue
            keep.add(cur)
            for prev in rev_adj.get(cur, ()):
                if prev not in keep:
                    stack.append(prev)

        # Keep only nodes/links on paths that end at this DEFEND root
        connected_nodes = [n for n in connected_nodes if n in keep]

        # Drop all non-root DEFEND nodes explicitly
        connected_nodes = [n for n in connected_nodes if not (n.startswith("D3-") and n != root_id)]

        # Prune links to match filtered nodes *and* only those that lead to the root DEFEND
        links = [(s, t) for (s, t) in links if s in connected_nodes and t in connected_nodes]


    # For non-CVE-rooted files: ensure all related CVEs appear (even if dangling)
    if root_type != "CVE":
        for cwe in data["Nodes"].get("CWE", []):
            for cve in ensure_list(cwe.get("Related_CVEs", [])):
                if cve not in connected_nodes:
                    connected_nodes.append(cve)
                if cve not in nodes:
                    nodes.append(cve)
                if cve not in node_info:
                    node_info[cve] = {
                        "Title": "CVE record (not expanded)",
                        "Description": "Auto-included from CWE relationships.",
                        "Source": f"https://nvd.nist.gov/vuln/detail/{cve}",
                    }

    # For CVE-rooted graphs: only keep the single input CVE visible
    if root_type == "CVE" and root_id:
        connected_nodes = [n for n in connected_nodes if not n.startswith("CVE") or n == root_id]

    # ------------------------------------------------------
    # Limit display for the root type (CWE, CAPEC) + prune links
    # ------------------------------------------------------
    if root_type == "CAPEC" and root_id:
        # Keep only the single CAPEC root (no other CAPECs),
        # but keep all other types (CWE/ATT&CK/D3FEND) that form the path.
        connected_nodes = [n for n in connected_nodes if not n.startswith("CAPEC-") or n == root_id]

    elif root_type == "CWE" and root_id:
        # Keep the root CWE and any parent CWEs; drop other CWEs.
        connected_nodes = [
            n for n in connected_nodes
            if not (n.startswith("CWE-") and n != root_id and n not in parent_cwe_nodes)
        ]

    # 🔪 PRUNE LINKS to match the filtered nodes (critical!)
    links = [(s, t) for (s, t) in links if s in connected_nodes and t in connected_nodes]

    # ♻️ Reset nodes so get_index() can't resurrect filtered nodes via leftover links
    nodes = []

    # ------------------------------------------------------
    # Collect node descriptions (only for connected)
    # ------------------------------------------------------
    for section in data["Nodes"]:
        for item in data["Nodes"][section]:
            node_id = (
                    item.get("CVE_ID")
                    or item.get("CWE_ID")
                    or item.get("CAPEC_ID")
                    or item.get("ATTACK")
                    or item.get("DEFEND")
            )
            if not node_id or node_id not in connected_nodes:
                continue

            # 🔍 Try all known source fields
            src = (
                    item.get("Source_Page")
                    or item.get("Source_API")
                    or item.get("Source")
                    or item.get("Source_URL")
                    or ""
            )

            # 🧭 Construct fallback URLs if missing
            if not src:
                if node_id.startswith("CVE-"):
                    src = f"https://nvd.nist.gov/vuln/detail/{node_id}"
                elif node_id.startswith("CWE-"):
                    try:
                        num = node_id.split("-")[1]
                        src = f"https://cwe.mitre.org/data/definitions/{num}.html"
                    except IndexError:
                        src = "https://cwe.mitre.org/"
                elif node_id.startswith("CAPEC-"):
                    try:
                        num = node_id.split("-")[1]
                        src = f"https://capec.mitre.org/data/definitions/{num}.html"
                    except IndexError:
                        src = "https://capec.mitre.org/"
                elif node_id.startswith("T"):
                    src = f"https://attack.mitre.org/techniques/{node_id}/"
                elif node_id.startswith("D3-"):
                    src = f"https://d3fend.mitre.org/technique/{node_id}/"

            # 🖱️ Make clickable
            if src and not src.startswith("<a"):
                src = f'<a href="{src}" target="_blank">{src}</a>'

            info = {
                "Title": item.get("Title", ""),
                "Description": item.get("Description", ""),
                "Source": src,
            }

            # Add CVSS for CVEs
            if section == "CVE":
                cvss = item.get("CVSS_Score") or item.get("CVSS", "")
                if cvss:
                    info["CVSS_Score"] = cvss

            node_info[node_id] = info

    # ------------------------------------------------------
    # Properly extract D3FEND technique source
    # ------------------------------------------------------
    for defend in data["Nodes"].get("DEFEND", []):
        defend_id = defend.get("DEFEND", "")
        if defend_id and defend_id in connected_nodes:
            defend_source = (
                    defend.get("attack.defense.url")
                    or defend.get("Source")
                    or defend.get("Source_Page")
                    or defend.get("Source_API")
                    or "https://d3fend.mitre.org/"
            )
            # 🖱️ Make clickable
            if defend_source and not defend_source.startswith("<a"):
                defend_source = f'<a href="{defend_source}" target="_blank">{defend_source}</a>'

            node_info[defend_id] = {
                "Title": defend.get("Title", "MITRE D3FEND Technique"),
                "Description": defend.get(
                    "Description",
                    "Defensive countermeasure from MITRE D3FEND framework."
                ),
                "Source": defend_source
            }

    # ------------------------------------------------------
    # Position by type
    # ------------------------------------------------------
    x_positions = {"CVE": 0.0, "CWE": 0.2, "CAPEC": 0.4, "T": 0.6, "D3-": 0.8}
    x_vals, y_vals = [], []
    groups = {"CVE": [], "CWE": [], "CAPEC": [], "T": [], "D3-": []}

    for n in connected_nodes:
        if n.startswith("CVE"):
            groups["CVE"].append(n)
        elif n.startswith("CWE"):
            groups["CWE"].append(n)
        elif n.startswith("CAPEC"):
            groups["CAPEC"].append(n)
        elif n.startswith("T"):
            groups["T"].append(n)
        elif n.startswith("D3-"):
            groups["D3-"].append(n)

    # for g, group_nodes in groups.items():
    #     for i, n in enumerate(sorted(group_nodes)):
    #         if n not in nodes:
    #             nodes.append(n)
    #         x_vals.append(x_positions[g])
    #         y_vals.append((i + 1) / (len(group_nodes) + 1))

    # Position by type
    x_positions = {"CVE": 0.0, "CWE": 0.2, "CAPEC": 0.4, "T": 0.6, "D3-": 0.8}

    x_vals, y_vals = [], []
    for g, group_nodes in groups.items():
        for i, n in enumerate(sorted(group_nodes)):
            if n not in nodes:
                nodes.append(n)
            x_vals.append(x_positions[g])
            y_vals.append((i + 1) / (len(group_nodes) + 1))

    # ------------------------------------------------------
    # Build Sankey data
    # ------------------------------------------------------
    if links:
        source, target = zip(*[(get_index(s), get_index(t)) for s, t in links])
    else:
        print("⚠️ No directional links found.")
        source, target = [], []

    # Colors (gradient for ancestry)
    base_blue = (52, 152, 219)  # #3498db
    def lighten(color, factor):
        return tuple(int(c + (255 - c) * factor) for c in color)

    colors = []
    for n in nodes:
            if n.startswith("CWE"):
                colors.append("#1c3546")
            elif n.startswith("CVE"):
                colors.append("#490067")
            elif n.startswith("CWE"):
                colors.append("#1c3546")
            elif n.startswith("CAPEC"):
                colors.append("#754821")
            elif n.startswith("T"):
                colors.append("#6c1b13")
            elif n.startswith("D3-"):
                colors.append("#145831")
            else:
                colors.append("#95a5a6")


    # Tooltips
    hover_texts = []
    for n in nodes:
        info = node_info.get(n, {})
        title = safe_field(info.get("Title", ""))
        desc = wrap_text(safe_field(info.get("Description", "")))
        src = safe_field(info.get("Source", f"https://d3fend.mitre.org/technique/{n}/" if n.startswith("D3-") else ""))
        tooltip = f"<b>ID: {n}</b><br><b>Title:</b> {title}<br><b>Source:</b> {src}<br><b>Description:</b><br>{desc}<br>"
        if info.get("CVSS_Score"):
            tooltip += f"<b>CVSS:</b> {info['CVSS_Score']}<br>"
        hover_texts.append(tooltip)

    # Plot
    fig = go.Figure(go.Sankey(
        node=dict(
            pad=10,
            thickness=13,
            line=dict(color="black", width=0.4),
            label=nodes,
            color=colors,
            customdata=hover_texts,
            hovertemplate="%{customdata}<extra></extra>",
            x=x_vals,
            y=y_vals
        ),
        link=dict(
            source=source,
            target=target,
            value=[1] * len(links),
            color="rgba(200,200,200,0.4)"
        )
    ))

    fig.update_layout(
        title_text=f"Directional Sankey for {filename}<br>({root_type}-rooted chain only)",
        font=dict(size=12, color="white"),
        paper_bgcolor="black",
        plot_bgcolor="black",
        height=900
    )

    # ------------------------------------------------------
    # Optional: Click-to-locate JSON node (console + editor)
    # ------------------------------------------------------
    import webbrowser
    import pathlib


    def find_node_in_json(node_id):
        """Search for a node ID inside its corresponding JSON file and print its location."""
        type_map = {
            "CVE": "CVEs.json",
            "CWE": "CWEs.json",
            "CAPEC": "CAPECs.json",
            "T": "ATTACKs.json",
            "D3-": "DEFENDs.json"
        }

        match_type = None
        for prefix in type_map:
            if node_id.startswith(prefix):
                match_type = prefix
                break

        if not match_type:
            print(f"⚠️ Could not determine file for ID {node_id}")
            return

        json_path = None
        for root, _, files in os.walk("."):
            for f in files:
                if f == type_map[match_type]:
                    json_path = os.path.join(root, f)
                    break
            if json_path:
                break

        if not json_path or not os.path.exists(json_path):
            print(f"⚠️ File not found for {node_id} → expected {type_map[match_type]}")
            return

        print(f"\n📂 Searching for {node_id} inside {json_path}...")
        with open(json_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for i, line in enumerate(lines):
            if node_id in line:
                start = max(0, i - 3)
                end = min(len(lines), i + 6)
                snippet = "".join(lines[start:end])
                print(f"📍 Found {node_id} near line {i + 1}:\n{'-' * 60}\n{snippet}\n{'-' * 60}")
                break
        else:
            print(f"❌ {node_id} not found in {json_path}")
            return

        # Open file in editor if you want
        try:
            abs_path = pathlib.Path(json_path).resolve()
            webbrowser.open(f"file://{abs_path}")
        except Exception as e:
            print(f"⚠️ Could not open file: {e}")


    fig.show()
# ✅ Add this at the end:
    __VIS_FIG__ = fig
    __VIS_FILENAME__ = filename
    __VIS_NODEINFO__ = node_info

'''

# #Tkinter display
import json, os, re, time, tkinter as tk, subprocess, shutil
from tkinter import messagebox
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


# ======================================================
# === Helper: find all roadmap JSONs
# ======================================================
def find_roadmap_jsons(base_dir="."):
    results = []
    for root, _, files in os.walk(base_dir):
        for f in files:
            if re.match(r"^roadmap_.*\.json$", f) and not f.lower().endswith("s.json"):
                results.append(os.path.join(root, f))
    return sorted(results)


# ======================================================
# === Helper: open JSON file and scroll to node
# ======================================================
def open_json_for_node(node_id, base_dir="."):
    mapping = {
        "CVE": "CVEs.json",
        "CWE": "CWEs.json",
        "CAPEC": "CAPECs.json",
        "T": "ATTACKs.json",
        "D3-": "DEFENDs.json",
    }
    file_target = None
    for prefix, filename in mapping.items():
        if node_id.startswith(prefix):
            for root, _, files in os.walk(base_dir):
                if filename in files:
                    file_target = os.path.join(root, filename)
                    break
    if not file_target:
        messagebox.showwarning("Not Found", f"No JSON file found for {node_id}")
        return
    try:
        subprocess.Popen(["notepad.exe", file_target])
    except Exception as e:
        messagebox.showerror("Error", f"Could not open file:\n{e}")


# ======================================================
# === Build Network from unified roadmap
# ======================================================
def build_graph(filepath):
    """Builds a directed graph (CVE→CWE→CAPEC→ATTACK→DEFEND) with robust link detection."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    G = nx.DiGraph()
    node_meta = {}
    valid_pattern = re.compile(r"^(CVE-\d{4}-\d+|CWE-\d+|CAPEC-\d+|T\d+(\.\d+)?|D3-[-A-Z0-9]+)$")
    def valid_id(x): return isinstance(x, str) and valid_pattern.match(x)

    for t, lst in data.get("Nodes", {}).items():
        for n in lst:
            node_id = n.get("CVE_ID") or n.get("CWE_ID") or n.get("CAPEC_ID") or n.get("ATTACK") or n.get("DEFEND")
            if valid_id(node_id):
                node_meta[node_id] = n
                G.add_node(node_id)

    def add_edges(src_field, rel_fields, src_key):
        for src in data["Nodes"].get(src_field, []):
            s = src.get(src_key)
            if not valid_id(s): continue
            for rel_field in rel_fields:
                related = src.get(rel_field, [])
                if isinstance(related, str): related = [related]
                for target in related:
                    if valid_id(target):
                        G.add_edge(s, target)

    add_edges("CVE", ["Related_CWEs", "Related_CWE"], "CVE_ID")
    add_edges("CWE", ["Related_CAPEC", "Related_CAPECs"], "CWE_ID")
    add_edges("CAPEC", ["Related_MITRE_ATT&CK", "Related_Attack"], "CAPEC_ID")
    add_edges("ATTACK", ["DEFEND"], "ATTACK")

    for cwe in data["Nodes"].get("CWE", []):
        cwe_id = cwe.get("CWE_ID")
        if not valid_id(cwe_id): continue
        related_cves = cwe.get("Related_CVEs", [])
        if isinstance(related_cves, str): related_cves = [related_cves]
        for cve in related_cves:
            if valid_id(cve): G.add_edge(cve, cwe_id)

    return G, node_meta


# ======================================================
# === Tkinter Graph Viewer
# ======================================================
class GraphViewer(tk.Tk):
    def __init__(self, roadmap_file):
        super().__init__()
        self.title(f"Interactive Roadmap: {os.path.basename(roadmap_file)}")
        self.geometry("1400x900")
        self.configure(bg="#1e1e1e")

        self.file_dir = os.path.dirname(roadmap_file)
        self.G, self.node_meta = build_graph(roadmap_file)

        # ----- layout -----
        # ----- layout (centered vertically) -----
        layers = {"CVE": 0, "CWE": 1, "CAPEC": 2, "T": 3, "D3-": 4}
        groups = {k: [] for k in layers}

        # group nodes by prefix
        for n in self.G.nodes():
            for pfx in layers:
                if n.startswith(pfx):
                    groups[pfx].append(n)

        # compute positions centered along Y-axis
        self.pos = {}
        for i, (pfx, nodes) in enumerate(groups.items()):
            nodes_sorted = sorted(nodes)
            count = len(nodes_sorted)
            if count == 0:
                continue
            # vertically center nodes around y=0
            start_y = -(count - 1) / 2.0
            for j, n in enumerate(sorted(nodes_sorted)):
                y = start_y + (count - 1 - j)  # ensures A–Z is top→bottom
                self.pos[n] = (i, y)

        # ----- figure -----
        self.fig, self.ax = plt.subplots(figsize=(14, 9))
        self.ax.set_facecolor("#0d0d0d")
        self.ax.axis("off")

        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.dragging = None
        self.last_click_time = 0
        self.last_node = None
        self._last_redraw = 0
        self._label_cache = {}

        # Draw initial
        self.draw_graph()

        # ----- info panel -----
        self.info_box = tk.Text(self, width=55, bg="#111", fg="white", wrap="word")
        self.info_box.pack(side=tk.RIGHT, fill=tk.Y)
        self.info_box.insert(tk.END, "🟣 Click node to see info.\n🟣 Double-click to open file.\n🟣 Drag nodes to move.\n")

        # Events
        self.canvas.mpl_connect("button_press_event", self.on_click)
        self.canvas.mpl_connect("button_release_event", self.on_release)
        self.canvas.mpl_connect("motion_notify_event", self.on_drag)

    # ==================================================
    # === Core Drawing Logic (optimized)
    # ==================================================
    def _get_text_size(self, label):
        """Cache text bounding boxes for speed."""
        if label in self._label_cache:
            return self._label_cache[label]
        text = self.ax.text(0, 0, label, fontsize=9, fontweight="bold", color="white")
        bb = text.get_window_extent(renderer=self.fig.canvas.get_renderer())
        text.remove()
        inv = self.ax.transData.inverted()
        bbox_data = inv.transform([[bb.x0, bb.y0], [bb.x1, bb.y1]])
        w, h = bbox_data[1, 0] - bbox_data[0, 0], bbox_data[1, 1] - bbox_data[0, 1]
        self._label_cache[label] = (w, h)
        return w, h

    def _color_for(self, node):
        if node.startswith("CVE"): return "#b32d00"
        if node.startswith("CWE"): return "#005c99"
        if node.startswith("CAPEC"): return "#996633"
        if node.startswith("T"): return "#663300"
        if node.startswith("D3-"): return "#00664d"
        return "#444"

    def draw_graph(self):
        """Initial draw."""
        self.ax.clear()
        self.ax.set_facecolor("#0d0d0d")
        self.ax.axis("off")
        nx.draw_networkx_edges(
            self.G, self.pos, ax=self.ax,
            edge_color="#666", arrows=True, arrowstyle="->",
            min_source_margin=0.1, min_target_margin=0.1,
            connectionstyle="arc3,rad=0.07"
        )

        for n in self.G.nodes():
            x, y = self.pos[n]
            w, h = self._get_text_size(n)
            pad_x, pad_y = 0.3, 0.18
            color = self._color_for(n)
            rect = FancyBboxPatch(
                (x - (w / 2 + pad_x / 2), y - (h / 2 + pad_y / 2)),
                w + pad_x, h + pad_y,
                boxstyle="round,pad=0.02,rounding_size=0.08",
                linewidth=1, edgecolor="white", facecolor=color, zorder=3
            )
            self.ax.add_patch(rect)
            self.ax.text(x, y, n, ha="center", va="center", fontsize=9,
                         color="white", fontweight="bold", zorder=4)

        self.ax.margins(0.15)
        self.canvas.draw_idle()

    # def update_node_position(self, node_id):
    #
    #     """Fast redraw when a node is moved."""
    #     for patch in list(self.ax.patches): patch.remove()
    #     for txt in list(self.ax.texts): txt.remove()
    #     for coll in list(self.ax.collections): coll.remove()
    #
    #     nx.draw_networkx_edges(
    #         self.G, self.pos, ax=self.ax,
    #         edge_color="#666", arrows=True, arrowstyle="->",
    #         min_source_margin=0.1, min_target_margin=0.1,
    #         connectionstyle="arc3,rad=0.07"
    #     )
    #
    #     for n in self.G.nodes():
    #         x, y = self.pos[n]
    #         w, h = self._get_text_size(n)
    #         pad_x, pad_y = 0.3, 0.18
    #         color = self._color_for(n)
    #         rect = FancyBboxPatch(
    #             (x - (w / 2 + pad_x / 2), y - (h / 2 + pad_y / 2)),
    #             w + pad_x, h + pad_y,
    #             boxstyle="round,pad=0.02,rounding_size=0.08",
    #             linewidth=1, edgecolor="white" if n != node_id else "yellow",
    #             facecolor=color, zorder=3
    #         )
    #         self.ax.add_patch(rect)
    #         self.ax.text(x, y, n, ha="center", va="center",
    #                      fontsize=9, color="white", fontweight="bold", zorder=4)
    #
    #     self.canvas.draw_idle()

    # ==================================================
    # === Interaction
    # ==================================================

    def update_node_position(self, node_id):
        """Redraw graph smoothly while dragging."""
        # Limit redraw rate (~30 FPS)
        now = time.time()
        if now - self._last_redraw < 0.03:
            return
        self._last_redraw = now

        self.ax.clear()
        self.ax.set_facecolor("#0d0d0d")
        self.ax.axis("off")

        # Draw edges from side-to-side
        for src, dst in self.G.edges():
            if src not in self.pos or dst not in self.pos:
                continue
            x1, y1 = self.pos[src]
            x2, y2 = self.pos[dst]
            w1, _ = self._get_text_size(src)
            w2, _ = self._get_text_size(dst)
            start_x = x1 + w1 / 2 + 0.2
            end_x = x2 - w2 / 2 - 0.2
            self.ax.annotate("",
                             xy=(end_x, y2), xytext=(start_x, y1),
                             arrowprops=dict(
                                 arrowstyle="->", color="#666", lw=1.0,
                                 shrinkA=0, shrinkB=0, connectionstyle="arc3,rad=0.05"
                             )
                             )

        # Redraw all nodes
        for n in self.G.nodes():
            x, y = self.pos[n]
            w, h = self._get_text_size(n)
            pad_x, pad_y = 0.3, 0.18
            color = self._color_for(n)
            rect = FancyBboxPatch(
                (x - (w / 2 + pad_x / 2), y - (h / 2 + pad_y / 2)),
                w + pad_x, h + pad_y,
                boxstyle="round,pad=0.02,rounding_size=0.08",
                linewidth=1,
                edgecolor="black" if n == node_id else "white",
                facecolor=color, zorder=3
            )
            self.ax.add_patch(rect)
            self.ax.text(x, y, n, ha="center", va="center",
                         fontsize=9, color="white", fontweight="bold", zorder=4)

        self.ax.margins(0.15)
        self.canvas.draw_idle()

    def find_nearest_node(self, x, y):
        nearest, dist = None, 0.3
        for n, (nx_, ny_) in self.pos.items():
            d = ((x - nx_) ** 2 + (y - ny_) ** 2) ** 0.5
            if d < dist:
                nearest, dist = n, d
        return nearest

    def show_info(self, node_id):
        meta = self.node_meta.get(node_id, {})
        self.info_box.delete("1.0", tk.END)
        self.info_box.insert(tk.END, f"🟪 Node: {node_id}\n\n")
        for k, v in meta.items():
            self.info_box.insert(tk.END, f"{k}: {v}\n\n")

    # def on_click(self, event):
    #     if not event.inaxes: return
    #     node = self.find_nearest_node(event.xdata, event.ydata)
    #     if not node: return
    #     now = time.time()
    #     if self.last_node == node and (now - self.last_click_time) < 0.5:
    #         self.open_json_for_node(node)
    #     else:
    #         self.show_info(node)
    #         self.dragging = node
    #     self.last_click_time, self.last_node = now, node
    #
    # def on_drag(self, event):
    #     """Update node position in real time while dragging."""
    #     if not self.dragging or not event.inaxes:
    #         return
    #     self.pos[self.dragging] = (event.xdata, event.ydata)
    #     self.update_node_position(self.dragging)
    #
    # def on_release(self, event):
    #     """Stop dragging when mouse button released."""
    #     if not self.dragging:
    #         return
    #     if event.inaxes:
    #         # Update node position
    #         self.pos[self.dragging] = (event.xdata, event.ydata)
    #         self.update_node_position(self.dragging)
    #     self.dragging = None

    def on_click(self, event):
        if not event.inaxes:
            return
        node = self.find_nearest_node(event.xdata, event.ydata)
        if not node:
            return

        now = time.time()
        # Handle double click
        if self.last_node == node and (now - self.last_click_time) < 0.4:
            self.open_json_for_node(node)
        else:
            self.show_info(node)
            self.dragging = node
            self._drag_started = False  # NEW flag to prevent accidental drags
            self._click_pos = (event.xdata, event.ydata)
        self.last_click_time, self.last_node = now, node

    def on_drag(self, event):
        """Start moving only after actual mouse movement."""
        if not self.dragging or not event.inaxes or self._click_pos is None:
            return

        dx = abs(event.xdata - self._click_pos[0])
        dy = abs(event.ydata - self._click_pos[1])

        # Start drag only after moving enough
        if not self._drag_started:
            if dx < 0.1 and dy < 0.1:  # sensitivity threshold
                return
            self._drag_started = True  # start real dragging now

        self.pos[self.dragging] = (event.xdata, event.ydata)
        self.update_node_position(self.dragging)

    def on_release(self, event):
        """Stop dragging when mouse button released."""
        self.dragging = None
        self._drag_started = False
        self._click_pos = None

    def open_json_for_node(self, node_id):
        """Open JSON file and jump to node."""
        mapping = {
            "CVE": "CVEs.json",
            "CWE": "CWEs.json",
            "CAPEC": "CAPECs.json",
            "T": "ATTACKs.json",
            "D3-": "DEFENDs.json",
        }
        file_target = None
        for prefix, filename in mapping.items():
            if node_id.startswith(prefix):
                for root, _, files in os.walk(self.file_dir):
                    if filename in files:
                        file_target = os.path.join(root, filename)
                        break
        if not file_target:
            messagebox.showwarning("Not Found", f"No JSON file found for {node_id}")
            return

        line_number = None
        with open(file_target, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                if node_id in line:
                    line_number = i
                    break

        npp_path = shutil.which("notepad++") or "C:\\Program Files\\Notepad++\\notepad++.exe"
        if npp_path and os.path.exists(npp_path) and line_number:
            subprocess.Popen([npp_path, f"-n{line_number}", file_target])
            return

        vscode_path = shutil.which("code")
        if vscode_path and line_number:
            subprocess.Popen([vscode_path, "-g", f"{file_target}:{line_number}"])
            return

        subprocess.Popen(["notepad.exe", file_target])
        if line_number:
            messagebox.showinfo("Opened", f"File opened. Line: {line_number}")



# ======================================================
# === Entry point
# ======================================================
if __name__ == "__main__":
    roadmaps = find_roadmap_jsons(".")
    if not roadmaps:
        print("❌ No roadmap JSONs found.")
        exit()

    print("\n📁 Available roadmaps:")
    for i, f in enumerate(roadmaps, 1):
        print(f" {i}. {f}")
    choice = input("Enter number: ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(roadmaps)):
        print("⚠️ Invalid.")
        exit()

    selected = roadmaps[int(choice) - 1]
    print(f"📂 Opening {selected}")
    app = GraphViewer(selected)
    app.mainloop()
