import requests
import re
import json
import logging
from bs4 import BeautifulSoup
from NLP_relationship_finder import link_nodes

def fetch_capec_data(capec_id):
    """
    Fetch CAPEC data from the MITRE CAPEC website.
    Example CAPEC page: https://capec.mitre.org/data/definitions/66.html
    """
    base_url = f"https://capec.mitre.org/data/definitions/{capec_id.replace('CAPEC-', '')}.html"
    response = requests.get(base_url)

    if response.status_code != 200:
        return {"error": f"Failed to fetch data. HTTP {response.status_code}", "CAPEC_ID": capec_id}

    try:
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        return {"error": f"Failed to parse HTML: {str(e)}", "CAPEC_ID": capec_id}

    # Extract CAPEC Title
    title_tag = soup.find("h2")
    title = title_tag.text.strip() if title_tag else None

    # Extract Description
    description = None
    desc_div = soup.find("div", {"id": "Description"})
    if desc_div:
        desc_p = soup.find("div", {"class": "indent"})
        if desc_p:
            description = desc_p.text.strip()

    # Extract Related CWEs
    related_cwes = []
    cwe_section = soup.find("div", {"id": "Related_Weaknesses"})
    if cwe_section:
        cwe_table = cwe_section.find_next("table")
        if cwe_table:
            for link in cwe_table.find_all("a", href=True):
                related_cwes.append("CWE-" + link.text.strip())

    # Extract Relationships (Parent/Child/Peer)
    relationships = []
    rel_section = soup.find("div", {"id": "Relationships"})
    if rel_section:
        rel_table = rel_section.find_next("table")
        if rel_table:
            for row in rel_table.find_all("tr")[1:]:  # skip header
                cols = [col.text.strip() for col in row.find_all("td")]
                if len(cols) >= 2:
                    relationships.append(f"{cols[0]}: {cols[2]}")

    # Extract Related MITRE ATT&CK Techniques
    mitre_attacks = []
    attack_section = soup.find("div", {"id": "Related_Attack_Patterns"})
    if not attack_section:
        attack_section = soup.find("div", {"id": "Taxonomy_Mappings"})
    if attack_section:
        attack_table = attack_section.find_next("table")
        if attack_table:
            for link in attack_table.find_all("a", href=True):
                href = link["href"]
                if "attack.mitre.org" in href:
                    mitre_attacks.append("T"+link.text.strip())

    # If no MITRE ATT&CK techniques found, try to fetch from parent CAPEC
    if not mitre_attacks:
        # Find Parent CAPEC ID from relationships
        parent_capec = None
        for rel in relationships:
            if rel.startswith("ChildOf:"):
                match = re.search(r'(\d+)', rel)
                if match:
                    parent_capec = match.group(1)
                    break

        # Recursively fetch parent's MITRE ATT&CK mapping if available
        if parent_capec:
            parent_data = fetch_capec_data(f"CAPEC-{parent_capec}")
            if parent_data.get("Related_MITRE_ATT&CK"):
                mitre_attacks = parent_data["Related_MITRE_ATT&CK"]

    # --- Likelihood of Attack ---
    likelihood = None
    likelihood_section = soup.find("div", {"id": "Likelihood_Of_Attack"})
    if likelihood_section:
        indent = likelihood_section.find_next("div", class_="indent")
        if indent:
            likelihood = indent.get_text(strip=True)

    # --- Typical Severity ---
    typical_severity = None
    severity_section = soup.find("div", {"id": "Typical_Severity"})
    if severity_section:
        indent = severity_section.find_next("div", class_="indent")
        if indent:
            typical_severity = indent.get_text(strip=True)

    # --- Execution Flow ---
    execution_flow = []
    exec_node = soup.find("div", {"id": "Execution_Flow"})
    if exec_node:
        content_root = exec_node.find(class_="expandblock") or exec_node.find(class_="tabledetail") or exec_node

        section_map = {}  # collect by section name

        for subhead in content_root.find_all(["div", "span"], class_=lambda c: c and "subhead" in c):
            section_name = subhead.get_text(" ", strip=True)
            ol = subhead.find_next_sibling("ol") or subhead.find_next("ol")
            if not ol:
                continue

            steps = []
            for li in ol.find_all("li", recursive=False):
                # step title
                bold = li.find("b")
                if bold:
                    step_text = bold.get_text(" ", strip=True)
                    bold.decompose()  # remove bold label
                    desc_text = li.get_text(" ", strip=True)
                    # clean redundant “Techniques” mention
                    desc_text = re.sub(r'\bTechniques\b.*', '', desc_text, flags=re.I).strip()
                    step_full = f"{step_text}: {desc_text}"
                else:
                    step_full = li.get_text(" ", strip=True)

                # collect techniques table
                techs = []
                tech_table = li.find("table")
                if tech_table:
                    for td in tech_table.find_all("td"):
                        t = td.get_text(" ", strip=True)
                        if t:
                            techs.append(t)

                steps.append({"step": step_full, "techniques": techs} if techs else {"step": step_full})

            # append or merge into section_map
            if section_name not in section_map:
                section_map[section_name] = steps
            else:
                section_map[section_name].extend(steps)

        # convert to list of grouped dicts
        for name, steps in section_map.items():
            execution_flow.append({
                "section": name,
                "steps": steps
            })

        # fallback: no subheads (rare)
        if not execution_flow:
            ol = content_root.find("ol")
            if ol:
                steps = []
                for li in ol.find_all("li", recursive=False):
                    step_text = li.get_text(" ", strip=True)
                    techs = []
                    tech_table = li.find("table")
                    if tech_table:
                        for td in tech_table.find_all("td"):
                            t = td.get_text(" ", strip=True)
                            if t:
                                techs.append(t)
                    steps.append({"step": step_text, "techniques": techs} if techs else {"step": step_text})
                execution_flow.append({"section": "Execution Flow", "steps": steps})

    # --- Prerequisites ---
    prerequisites = None
    prereq_node = soup.find(string=re.compile(r'Prerequisites', flags=re.I))
    if prereq_node:
        texts = []
        current = prereq_node.parent
        while current:
            current = current.find_next_sibling()
            if not current:
                break
            text = current.get_text(" ", strip=True)
            if not text:
                continue
            if re.match(r'(Skills Required|Resources Required|Consequences|Mitigations|Example Instances)', text,
                        flags=re.I):
                break
            texts.append(text)
        prerequisites = "\n\n".join(texts) if texts else None

    # --- Skills Required ---
    skills_required = None
    skills_node = soup.find(string=re.compile(r'Skills Required', flags=re.I))
    if skills_node:
        texts = []
        current = skills_node.parent
        while current:
            current = current.find_next_sibling()
            if not current:
                break
            text = current.get_text(" ", strip=True)
            if not text:
                continue
            if re.match(r'(Resources Required|Consequences|Mitigations|Example Instances)', text, flags=re.I):
                break
            texts.append(text)
        skills_required = "\n\n".join(texts) if texts else None

    # --- Resources Required ---
    resources_required = None
    res_node = soup.find(string=re.compile(r'Resources Required', flags=re.I))
    if res_node:
        texts = []
        current = res_node.parent
        while current:
            current = current.find_next_sibling()
            if not current:
                break
            text = current.get_text(" ", strip=True)
            if not text:
                continue
            if re.match(r'(Consequences|Mitigations|Example Instances)', text, flags=re.I):
                break
            texts.append(text)
        resources_required = "\n\n".join(texts) if texts else None

    # --- Consequences ---
    consequences = []
    cons_node = soup.find(string=re.compile(r'Consequences', flags=re.I))
    if cons_node:
        tbl = cons_node.parent.find_next("table")
        if tbl:
            for tr in tbl.find_all("tr")[1:]:
                tds = tr.find_all("td")
                if not tds:
                    continue

                # preserve line breaks inside cells
                def split_cell(td):
                    txt = td.get_text("\n", strip=True)
                    parts = [p for p in re.split(r'[\r\n]+', txt) if p.strip()]
                    return parts or ["-"]

                scopes = split_cell(tds[0]) if len(tds) > 0 else ["-"]
                impacts = split_cell(tds[1]) if len(tds) > 1 else ["-"]
                likes = split_cell(tds[2]) if len(tds) > 2 else ["-"]

                # if impact/likelihood are singletons, repeat them for each scope
                if len(impacts) == 1 and len(likes) == 1:
                    for s in scopes:
                        consequences.append({
                            "Scope": s,
                            "Impact": impacts[0],
                            "Likelihood": likes[0]
                        })
                else:
                    # align by index, falling back to last item if lengths differ
                    m = max(len(scopes), len(impacts), len(likes))
                    for i in range(m):
                        consequences.append({
                            "Scope": scopes[min(i, len(scopes) - 1)],
                            "Impact": impacts[min(i, len(impacts) - 1)],
                            "Likelihood": likes[min(i, len(likes) - 1)]
                        })

    # --- Mitigations ---
    mitigations = []
    mit_node = soup.find(string=re.compile(r'Mitigations', flags=re.I))
    if mit_node:
        current = mit_node.parent
        while current:
            current = current.find_next_sibling()
            if not current:
                break
            text = current.get_text(" ", strip=True)
            if not text:
                continue
            if re.match(r'(Example Instances|Related Weaknesses|Taxonomy Mappings)', text, flags=re.I):
                break
            mitigations.append(text)

    # --- Example Instances ---
    example_instances = []
    ex_node = soup.find(string=re.compile(r'Example Instances', flags=re.I))
    if ex_node:
        current = ex_node.parent
        while current:
            current = current.find_next_sibling()
            if not current:
                break
            text = current.get_text(" ", strip=True)
            if not text:
                continue
            if re.match(r'(Related Weaknesses|Taxonomy Mappings|Content History)', text, flags=re.I):
                break
            example_instances.append(text)

    if not related_cwes:
        try:
            logging.info(f"No CWE links found for {capec_id}, inferring via NLP hybrid model...")
            ranked = link_nodes(description, "CWE", limit=500)
            related_cwes = [r[0].get("CWE_ID", "?") for r in ranked[:5]]
        except Exception as e:
            logging.warning(f"Hybrid inference failed for {capec_id}: {e}")
    elif not mitre_attacks:
        try:
            logging.info(f"No ATT&CK links found for {capec_id}, inferring via NLP hybrid model...")
            ranked = link_nodes(description, "ATTACK", limit=300)
            mitre_attacks = [r[0].get("ATTACK_ID", "?") for r in ranked[:5]]
        except Exception as e:
            logging.warning(f"Hybrid inference failed for {capec_id}: {e}")


    return {
        "CAPEC_ID": capec_id,
        "Title": title,
        "Description": description,
        "Likelihood_Of_Attack": likelihood,
        "Typical_Severity": typical_severity,
        "Execution_Flow": execution_flow,
        "Prerequisites": prerequisites,
        "Skills_Required": skills_required,
        "Resources_Required": resources_required,
        "Consequences": consequences,
        "Mitigations": mitigations,
        "Example_Instances": example_instances,
        "Related_CWEs": related_cwes,
        "Relationships": relationships,
        "Related_MITRE_ATT&CK": mitre_attacks,
        "Source_Page": base_url
    }
