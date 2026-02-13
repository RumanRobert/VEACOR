#DASH DISPLAY
import os
import re
import json
import subprocess
import shutil
from pathlib import Path
import threading
import webbrowser
import time

import dash
from dash import html, dcc, Input, Output, State
import dash_cytoscape as cyto

# NEW: deterministic layout
import networkx as nx

# -------------------------------------------------------------------
# Base directory
# -------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parents[2]  # project root
OUTPUT_DIR = BASE_DIR / "outputs"

# -------------------------------------------------------------------
# Find roadmap_*.json files
# -------------------------------------------------------------------
from pathlib import Path

def find_roadmap_jsons(base_dir=OUTPUT_DIR):
    results = []
    pattern = re.compile(r"^roadmap_.*\.json$", re.IGNORECASE)
    for root, _, files in os.walk(base_dir):
        for f in files:
            if pattern.match(f) and not f.lower().endswith("s.json"):
                results.append(os.path.join(root, f))
    return sorted(results)



# -------------------------------------------------------------------
# Open underlying CVEs.json / CWEs.json / CAPECs.json / ATTACKs.json / DEFENDs.json
# on double-click
# -------------------------------------------------------------------
def open_json_for_node(node_id, base_dir=BASE_DIR):
    mapping = {
        "cpe": "CPEs.json",
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
        print(f"[WARN] No JSON file found for {node_id}")
        return

    # Try to find node in file for nicer editor jump
    line_number = None
    try:
        with open(file_target, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                if node_id in line:
                    line_number = i
                    break
    except Exception as e:
        print("[ERROR] While scanning JSON:", e)

    # Notepad++
    npp_path = shutil.which("notepad++") or "C:\\Program Files\\Notepad++\\notepad++.exe"
    if npp_path and os.path.exists(npp_path) and line_number:
        subprocess.Popen([npp_path, f"-n{line_number}", file_target])
        return

    # VS Code
    code_path = shutil.which("code")
    if code_path and line_number:
        subprocess.Popen([code_path, "-g", f"{file_target}:{line_number}"])
        return

    # Fallback: Notepad
    subprocess.Popen(["notepad.exe", file_target])

def normalize_id(nid: str):
    if not isinstance(nid, str):
        return None
    return nid.replace(" - NLP Link", "").strip()


# -------------------------------------------------------------------
# NEW: Deterministic "related nodes cluster" positions, but still column-based by type
# -------------------------------------------------------------------
def compute_positions_grid_clustered(
    nodes,
    edges,
    base_y_gap=36,
    extra_gap=28,
    x_gap=260,
    seed=42,
    center_padding=0,
    score_threshold=0.08,   # raise => more gaps, lower => tighter packing
    hub_exponent=0.75,      # higher => hubs contribute even less
):
    import networkx as nx

    G = nx.Graph()
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)

    # Used only for ordering (not for absolute positions)
    spring_pos = nx.spring_layout(G, seed=seed, iterations=300)

    layers = {"CPE": 0, "CVE": 1, "CWE": 2, "CAPEC": 3, "T": 4, "D3-": 5}

    def node_type(nid):
        if isinstance(nid, str) and nid.lower().startswith("cpe:"):
            return "CPE"
        for k in layers:
            if isinstance(nid, str) and nid.startswith(k):
                return k
        return "OTHER"

    # Group nodes by column
    columns = {}
    for n in nodes:
        columns.setdefault(node_type(n), []).append(n)

    # Precompute neighbors and degrees for fast relatedness scoring
    neighbor_sets = {n: set(G.neighbors(n)) for n in G.nodes()}
    deg = dict(G.degree())

    def related_score(a, b):
        """
        How 'close' should a and b be in the SAME column?
        - Direct edge => extremely close
        - Shared neighbors => close, but shared HUB neighbors count less
        """
        if G.has_edge(a, b):
            return 1e9

        shared = neighbor_sets.get(a, set()) & neighbor_sets.get(b, set())
        if not shared:
            return 0.0

        score = 0.0
        for u in shared:
            d = deg.get(u, 1)
            score += 1.0 / (d ** hub_exponent)
        return score

    positions = {}

    for col_name, col_nodes in columns.items():
        col_index = layers.get(col_name, 5)

        # Sort by spring Y (helps cluster related nodes)
        col_nodes.sort(key=lambda n: spring_pos.get(n, (0, 0))[1])

        # --- First pass: compute raw y coordinates (grid with adaptive gaps) ---
        y = 0
        ys = []
        prev = None

        for n in col_nodes:
            if prev is not None:
                score = related_score(prev, n)

                # Insert extra blank space only if "weakly related"
                if score < score_threshold:
                    y += extra_gap

                y += base_y_gap

            ys.append(y)
            prev = n

        # --- Center the column around y=0 ---
        if ys:
            y_mid = (ys[0] + ys[-1]) / 2.0
        else:
            y_mid = 0.0

        # --- Second pass: assign positions with centered y ---
        for n, y_raw in zip(col_nodes, ys):
            positions[n] = {
                "x": col_index * x_gap,
                "y": float(y_raw - y_mid + center_padding),
            }

    return positions





# -------------------------------------------------------------------
# Build graph from a single roadmap_*.json
# -------------------------------------------------------------------
def build_graph_from_json(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    valid_pattern = re.compile(
        r"^(?:"
        r"cpe:2\.3:[aho]:(?:[^:]*:){9}[^:]*"
        r"|CVE-\d{4}-\d+"
        r"|CWE-\d+"
        r"|CAPEC-\d+"
        r"|T\d+(\.\d+)?"
        r"|D3-[-A-Z0-9]+"
        r")$",
        re.IGNORECASE
    )

    def valid_id(x):
        return isinstance(x, str) and valid_pattern.match(x)

    nodes_set = set()
    node_meta = {}
    edges = []

    # ---- collect nodes and base metadata ----
    for t, lst in data.get("Nodes", {}).items():
        for n in lst:
            node_id = (
                    n.get("CVE_ID")
                    or n.get("CWE_ID")
                    or n.get("CAPEC_ID")
                    or n.get("ATTACK")
                    or n.get("DEFEND")
                    or n.get("CPE_ID")
            )

            if node_id and "cpe:" in node_id.lower():
                print("RAW CPE FROM JSON:", repr(node_id))
            clean = normalize_id(node_id)

            if valid_id(clean):
                nodes_set.add(clean)

                if clean not in node_meta:
                    node_meta[clean] = n

                node_meta[clean]["raw_id"] = node_id

    # ---- helpers to add edges between node types ----
    nodes_set = {normalize_id(n) for n in nodes_set}

    def add_edges_from(section, rel_fields, src_key, reverse=False):
        for src in data.get("Nodes", {}).get(section, []):
            raw_src = src.get(src_key)
            s = normalize_id(raw_src)

            if not valid_id(s) or s not in nodes_set:
                continue

            for rel_field in rel_fields:
                related = src.get(rel_field, [])
                if isinstance(related, str):
                    related = [related]

                for target in related:
                    t = normalize_id(target)

                    if valid_id(t) and t in nodes_set:
                        if not reverse:
                            edges.append((s, t))
                        else:
                            edges.append((t, s))

    add_edges_from("CPE", ["Related_CVEs", "Related_CVE"], "CPE_ID")
    add_edges_from("CVE", ["Related_CWEs", "Related_CWE"], "CVE_ID")              # CVE → CWE
    add_edges_from("CWE", ["Related_CAPEC", "Related_CAPECs"], "CWE_ID")          # CWE → CAPEC
    add_edges_from("CAPEC", ["Related_MITRE_ATT&CK", "Related_Attack"], "CAPEC_ID")  # CAPEC → ATT&CK
    add_edges_from("ATTACK", ["DEFEND"], "ATTACK")                                # ATTACK → DEFEND

    # Also add CVE → CWE based on CWE.Related_CVEs (reverse),
    # but ONLY if the CVE node already exists in nodes_set.
    for cwe in data.get("Nodes", {}).get("CWE", []):
        cwe_id = normalize_id(cwe.get("CWE_ID"))
        if not valid_id(cwe_id) or cwe_id not in nodes_set:
            continue

        related_cves = cwe.get("Related_CVEs", [])
        if isinstance(related_cves, str):
            related_cves = [related_cves]

        for cve in related_cves:
            cv = normalize_id(cve)
            if valid_id(cv) and cv in nodes_set:
                edges.append((cv, cwe_id))

    add_edges_from("CAPEC", ["Related_CWEs"], "CAPEC_ID", reverse=True)
    add_edges_from("CWE", ["Related_CVEs"], "CWE_ID", reverse=True)
    add_edges_from("DEFEND", ["RELATED_ATTACKS"], "DEFEND", reverse=True)
    add_edges_from("ATTACK", ["Related_CAPEC"], "ATTACK", reverse=True)

    edges = [(src, dst) for (src, dst) in edges if src in nodes_set and dst in nodes_set]
    nodes = sorted(nodes_set)

    # ---- build node_info (Title, Description, Source) ----
    node_info = {}
    for nid, meta in node_meta.items():
        if nid.lower().startswith("cpe:"):
            node_info[nid] = {
                "Vendor": meta.get("Vendor", ""),
                "Product": meta.get("Product", ""),
                "Version": meta.get("Version", ""),
                "Part": meta.get("Part", ""),
            }
        else:
            title = meta.get("Title", "")
            desc = meta.get("Description", "")
            src = (
                meta.get("Source_Page")
                or meta.get("Source_API")
                or meta.get("Source")
                or meta.get("Source_URL")
                or ""
            )

            if not src:
                if nid.startswith("CVE-"):
                    src = f"https://www.cve.org/CVERecord?id={nid}"
                elif nid.startswith("CWE-"):
                    try:
                        num = nid.split("-")[1]
                        src = f"https://cwe.mitre.org/data/definitions/{num}.html"
                    except Exception:
                        src = "https://cwe.mitre.org/"
                elif nid.startswith("CAPEC-"):
                    try:
                        num = nid.split("-")[1]
                        src = f"https://capec.mitre.org/data/definitions/{num}.html"
                    except Exception:
                        src = "https://capec.mitre.org/"
                elif nid.startswith("T"):
                    src = f"https://attack.mitre.org/techniques/{nid}/"
                elif nid.startswith("D3-"):
                    src = f"https://d3fend.mitre.org/technique/{nid}/"

            node_info[nid] = {"Title": title, "Description": desc, "Source": src}

    # NEW: positions computed outside (in update_graph) so no more "spread by sorted list"
    return nodes, edges, node_info


def strip_nlp(id_str):
    return id_str.replace(" - NLP Link", "")


def make_cytoscape_elements(nodes, edges, node_info, positions):
    elements = []

    for nid in nodes:
        info = node_info.get(nid, {})

        if nid.startswith("CVE-"):
            ntype = "CVE"
        elif nid.startswith("CWE-"):
            ntype = "CWE"
        elif nid.startswith("CAPEC-"):
            ntype = "CAPEC"
        elif nid.startswith("T"):
            ntype = "ATTACK"
        elif nid.startswith("D3-"):
            ntype = "DEFEND"
        elif nid.startswith("cpe:"):
            ntype = "CPE"
        else:
            ntype = "OTHER"

        elements.append({
            "data": {
                "id": nid,
                "raw_id": nid,
                "label": nid,
                "type": ntype,
                "Title": info.get("Title", ""),
                "Description": info.get("Description", ""),
                "Source": info.get("Source", ""),
            },
            "position": positions[nid],
        })

    for src, dst in edges:
        elements.append({
            "data": {
                "id": f"{src}->{dst}",
                "source": src,
                "target": dst,
            }
        })

    return elements


# -------------------------------------------------------------------
# Cytoscape stylesheet (colors like your Matplotlib/Tkinter version)
# -------------------------------------------------------------------
stylesheet = [
    {
        "selector": "node",
        "style": {
            "label": "data(label)",
            "text-valign": "center",
            "color": "#FFFFFF",
            "font-size": "10px",
            "background-color": "#444444",
            "shape": "round-rectangle",
            "width": "label",
            "height": "label",
            "padding": "8px",
            "border-width": 1,
            "border-color": "#FFFFFF",
        },
    },
    {
        "selector": 'node[label *=" - NLP Link"]',
        "style": {
            "background-color": "#cc00cc",
            "border-color": "#ff00ff",
            "color": "white"
        },
    },
    {"selector": 'node[type = "CVE"]', "style": {"background-color": "#b32d00"}},
    {"selector": 'node[type = "CPE"]', "style": {"background-color": "#b10d88"}},
    {"selector": 'node[type = "CWE"]', "style": {"background-color": "#005c99"}},
    {"selector": 'node[type = "CAPEC"]', "style": {"background-color": "#996633"}},
    {"selector": 'node[type = "ATTACK"]', "style": {"background-color": "#663300"}},
    {"selector": 'node[type = "DEFEND"]', "style": {"background-color": "#00664d"}},
    {
        "selector": "edge",
        "style": {
            "line-color": "#888888",
            "width": 1,
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#888888",
            "curve-style": "bezier",
        },
    },
    {
        "selector": ":selected",
        "style": {
            "border-width": 2,
            "border-color": "#FFFF00",
            "line-color": "#FFFF00",
            "target-arrow-color": "#FFFF00",
        },
    },
]


# -------------------------------------------------------------------
# Dash app
# -------------------------------------------------------------------
roadmaps = find_roadmap_jsons()

app = dash.Dash("VEACOR")

app.layout = html.Div(
    style={"backgroundColor": "#111111", "color": "white", "height": "100vh"},
    children=[
        dcc.Store(id="node-metadata"),
        dcc.Store(id="selected-node"),
        dcc.Store(id="all-elements"),

        html.Div(
            style={"padding": "10px"},
            children=[
                html.H2("Attack Graph Viewer"),
                dcc.Dropdown(
                    id="file-select",
                    options=[
                        {"label": os.path.relpath(f, BASE_DIR), "value": f}
                        for f in roadmaps
                    ],
                    placeholder="Select a roadmap_*.json file...",
                    style={"width": "60%", "color": "#000000"},
                ),
            ],
        ),
        html.Div(
            style={"display": "flex", "height": "85vh"},
            children=[
                cyto.Cytoscape(
                    id="attack-graph",
                    layout={"name": "preset"},  # positions are fixed by us
                    style={
                        "width": "75%",
                        "height": "100%",
                        "backgroundColor": "#0d0d0d",
                    },
                    elements=[],
                    stylesheet=stylesheet,
                    wheelSensitivity=0.2,
                ),
                html.Div(
                    id="info-panel",
                    style={
                        "width": "25%",
                        "height": "100%",
                        "padding": "10px",
                        "overflowY": "auto",
                        "backgroundColor": "#111111",
                        "borderLeft": "1px solid #333333",
                    },
                    children="Select a file and click a node to see details.",
                ),
            ],
        ),
    ],
)

# -------------------------------------------------------------------
# Callbacks
# -------------------------------------------------------------------
@app.callback(
    Output("attack-graph", "elements"),
    Output("node-metadata", "data"),
    Output("all-elements", "data"),
    Input("file-select", "value"),
)
def update_graph(selected_file):
    if not selected_file:
        return [], {}, []

    nodes, edges, node_info = build_graph_from_json(selected_file)

    # NEW: clustered, deterministic positions (related nodes start close)
    positions = compute_positions_grid_clustered(nodes, edges)

    elements = make_cytoscape_elements(nodes, edges, node_info, positions)
    return elements, node_info, elements


_last_click = {"id": None, "time": 0.0}

@app.callback(
    Output("selected-node", "data"),
    Input("attack-graph", "tapNodeData"),
)
def store_selected_node(node_data):
    if not node_data:
        return None
    return node_data.get("id")


@app.callback(
    Output("info-panel", "children"),
    Input("attack-graph", "tapNodeData"),
    State("node-metadata", "data"),
)
def on_tap_node(node_data, metadata):
    global _last_click

    if not node_data or not metadata:
        return "Select a file and click a node to see details."

    clean_id = node_data.get("id")
    raw_id = node_data.get("raw_id", clean_id)

    info = metadata.get(raw_id) or metadata.get(clean_id, {})

    # --- handle double-click ---
    now = time.time()
    if _last_click["id"] == clean_id and (now - _last_click["time"]) < 0.4:
        open_json_for_node(clean_id)
    _last_click = {"id": clean_id, "time": now}

    children = [html.H3(raw_id)]

    if clean_id.lower().startswith("cpe:"):
        children.extend([
            html.P(f"Vendor: {info.get('Vendor', '')}"),
            html.P(f"Product: {info.get('Product', '')}"),
            html.P(f"Version: {info.get('Version', '')}"),
            html.P(f"Part: {info.get('Part', '')}"),
        ])
    else:
        children.extend([
            html.H4(info.get("Title", "")),
            html.P(info.get("Description", "")),
        ])

        src = info.get("Source", "")
        if src:
            children.append(
                html.P([
                    "Source: ",
                    html.A(
                        src,
                        href=src,
                        target="_blank",
                        style={"color": "#4FA3FF"}
                    )
                ])
            )

    return children


def get_relevant_connections(selected, elements):
    forward = {}
    backward = {}

    for el in elements:
        data = el.get("data", {})
        if "source" in data:
            s = data["source"]
            t = data["target"]
            forward.setdefault(s, []).append(t)
            backward.setdefault(t, []).append(s)

    connected_nodes = set()
    connected_edges = set()

    def add_edge(a, b):
        connected_edges.add(f"{a}->{b}")

    backward_layer = {selected}
    for _ in range(3):
        next_layer = set()
        for node in backward_layer:
            for src in backward.get(node, []):
                if src not in connected_nodes:
                    connected_nodes.add(src)
                    add_edge(src, node)
                    next_layer.add(src)
        backward_layer = next_layer

    forward_layer = {selected}
    for _ in range(3):
        next_layer = set()
        for node in forward_layer:
            for dst in forward.get(node, []):
                if dst not in connected_nodes:
                    connected_nodes.add(dst)
                    add_edge(node, dst)
                    next_layer.add(dst)
        forward_layer = next_layer

    return connected_nodes, connected_edges


@app.callback(
    Output("attack-graph", "stylesheet"),
    Input("selected-node", "data"),
    State("all-elements", "data"),
)
def update_stylesheet(selected, elements):
    base = stylesheet.copy()

    if not selected or not elements:
        return base

    connected_nodes, connected_edges = get_relevant_connections(selected, elements)

    base.append({"selector": "node, edge", "style": {"opacity": 0.25}})

    base.append({
        "selector": f'node[id = "{selected}"]',
        "style": {
            "opacity": 1.0,
            "border-width": 3,
            "border-color": "#ffff66"
        }
    })

    for nid in connected_nodes:
        base.append({
            "selector": f'node[id = "{nid}"]',
            "style": {"opacity": 1.0}
        })

    for eid in connected_edges:
        base.append({
            "selector": f'edge[id = "{eid}"]',
            "style": {"opacity": 1.0, "width": 2}
        })

    return base


def run_app():
    def open_browser():
        time.sleep(1)
        webbrowser.open("http://127.0.0.1:8050")


    threading.Thread(target=open_browser).start()
    app.run(debug=True, dev_tools_ui=False, use_reloader=False)


def main() -> int:
    run_app()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
