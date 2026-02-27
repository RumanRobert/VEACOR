import requests
import json
import logging
import re
from bs4 import BeautifulSoup
from veacor.Retrieves.NLP_relationship_finder import link_nodes, GLOBAL_MATCHER

def get_section(soup, base_id, cwe_id):
    """
    Locate a CWE section reliably by its ID.
    Tries both the static and CWE-numbered ID variants.
    Example: "Potential_Mitigations" or "Potential_Mitigations_79".
    """
    section = soup.find("div", {"id": f"{base_id}_{cwe_id.replace('CWE-', '').strip()}"})
    if not section:
        section = soup.find("div", {"id": base_id})
    return section


def fetch_cwe_data(cwe_id, visited=None):
    """
    Fetch CWE data from MITRE CWE.
    """
    # Normalize CWE ID → keep only number
    m = re.search(r"CWE-(\d+)", str(cwe_id), flags=re.I)
    cwe_id = f"CWE-{m.group(1)}" if m else cwe_id

    if visited is None:
        visited = set()
    if cwe_id in visited:
        return {"error": f"Circular reference detected for {cwe_id}", "CWE_ID": cwe_id}
    visited.add(cwe_id)

    base_url = f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html"
    response = requests.get(base_url, timeout=15)
    response.encoding = "utf-8"

    if response.status_code != 200:
        return {"error": f"Failed to fetch data. HTTP {response.status_code}", "CWE_ID": cwe_id}

    try:
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        return {"error": f"Failed to parse HTML: {str(e)}", "CWE_ID": cwe_id}



    # --- Title ---
    title_tag = soup.find("h2")
    title = title_tag.text.strip() if title_tag else None

    # --- Description (prefer Extended Description if available, merge both) ---
    description = ""

    # --- Try Extended Description first ---
    ext_desc_tag = soup.find("div", {"id": "Extended_Description"})
    if ext_desc_tag:
        indent_div = ext_desc_tag.find("div", class_="indent")
        if indent_div:
            ext_text = indent_div.get_text(" ", strip=True)
        else:
            text_parts = [
                t for t in ext_desc_tag.stripped_strings
                if not any(bad in t.lower() for bad in ["extended description", "toggleblocksoc"])
            ]
            ext_text = " ".join(text_parts).strip()
        if ext_text:
            description += ext_text.strip()

    # --- Then (optionally) add short Description if available ---
    desc_tag = soup.find("div", {"id": "Description"})
    if desc_tag:
        indent_div = desc_tag.find("div", class_="indent")
        if indent_div:
            short_text = indent_div.get_text(" ", strip=True)
        else:
            text_parts = [
                t for t in desc_tag.stripped_strings
                if not any(bad in t.lower() for bad in ["description", "toggleblocksoc"])
            ]
            short_text = " ".join(text_parts).strip()
        if short_text and short_text not in description:
            # Append with spacing if Extended already exists
            if description:
                description += " " + short_text
            else:
                description = short_text

    # Final cleanup
    description = description.strip() or None

    # --- Related CAPECs ---
    capec_ids = []
    capec_section = soup.find("div", {"id": "Related_Attack_Patterns"})
    if capec_section:
        capec_table = capec_section.find_next("table")
        if capec_table:
            for link in capec_table.find_all("a", href=True):
                if "CAPEC-" in link.text:
                    capec_ids.append(link.text.strip())

    # --- Related CVEs ---
    related_cves = []
    cves_section = soup.find("div", {"id": "Observed_Examples"})
    if cves_section:
        cve_table = cves_section.find_next("table")
        if cve_table:
            for link in cve_table.find_all("a", href=True):
                if "CVE-" in link.text:
                    related_cves.append(link.text.strip())

    # --- Relationships ---
    relationships = []
    rel_section = soup.find("div", {"id": "Relationships"})
    if rel_section:
        rel_table = rel_section.find_next("table")
        if rel_table:
            for row in rel_table.find_all("tr")[1:]:
                cols = [td.get_text(strip=True) for td in row.find_all("td")]
                if len(cols) >= 3:
                    relationships.append({
                        "Nature": cols[0],
                        "CWE_ID": cols[1],
                        "Name": cols[2]
                    })

    # --- Common Consequences ---
    consequences = []
    cons_section = soup.find("div", {"id": "Common_Consequences"})
    if cons_section:
        cons_table = cons_section.find_next("table")
        if cons_table:
            headers = [th.get_text(strip=True) for th in cons_table.find_all("th")]
            for row in cons_table.find_all("tr")[1:]:
                cols = [td.get_text(strip=True) for td in row.find_all("td")]
                if cols:
                    consequences.append(dict(zip(headers, cols)))

    # --- Likelihood of Exploit ---
    likelihood = None
    likelihood_section = get_section(soup, "Likelihood_Of_Exploit", cwe_id)
    if likelihood_section:
        indent = likelihood_section.find_next("div", class_="indent")
        if indent:
            likelihood = indent.get_text(strip=True)

    # --- Memberships ---
    memberships = []
    membership_section = soup.find("div", {"id": "Memberships"})
    if membership_section:
        table = membership_section.find_next("table")
        if table:
            for row in table.find_all("tr")[1:]:
                cols = [td.get_text(strip=True) for td in row.find_all("td")]
                if len(cols) >= 2:
                    memberships.append({
                        "Nature": cols[0],
                        "Type": cols[1],
                        "ID": "CWE-" + cols[2],
                        "Name": cols[3]
                    })

    # --- Detection Methods ---
    detection_methods = []
    detect_section = get_section(soup, "Detection_Methods", cwe_id)
    if detect_section:
        table = detect_section.find_next("table")
        if table:
            for row in table.find_all("tr")[1:]:
                cols = [td.get_text(strip=True) or "-" for td in row.find_all("td")]
                if len(cols) >= 2:
                    detection_methods.append({
                        "Method": cols[0],
                        "Details": cols[1] if len(cols) > 1 else "-"
                    })
        else:
            for blk in detect_section.find_all(["div", "p"]):
                txt = blk.get_text(" ", strip=True)
                if txt:
                    detection_methods.append({"Method": txt})

    # --- Vulnerability Mapping Notes ---
    mapping_notes = {}
    mapping_section = get_section(soup, "Vulnerability_Mapping_Notes", cwe_id)
    if mapping_section:
        table = mapping_section.find_next("table")
        if table:
            for row in table.find_all("tr"):
                cells = row.find_all("td")
                if len(cells) == 2:
                    key = cells[0].get_text(strip=True)
                    value = " ".join(str(cells[1].get_text(" ", strip=True)).split())
                    mapping_notes[key] = value

    # --- Taxonomy Mappings ---
    taxonomy_mappings = []
    taxonomy_section = soup.find("div", {"id": "Taxonomy_Mappings"})
    if taxonomy_section:
        table = taxonomy_section.find_next("table")
        if table:
            for row in table.find_all("tr")[1:]:
                cols = [td.get_text(strip=True) or "-" for td in row.find_all("td")]
                if len(cols) >= 4:
                    taxonomy_mappings.append({
                        "Mapped Taxonomy Name": cols[0],
                        "Node ID": cols[1],
                        "Fit": cols[2],
                        "Mapped Node Name": cols[3]
                    })

    # --- Weakness Ordinality ---
    weakness_ordinalities = []
    ordinality_section = get_section(soup, "Weakness_Ordinalities", cwe_id)
    if ordinality_section:
        table = ordinality_section.find_next("table")
        if table:
            for row in table.find_all("tr")[1:]:
                cols = [td.get_text(strip=True) or "-" for td in row.find_all("td")]
                if len(cols) >= 2:
                    weakness_ordinalities.append({
                        "Ordinality": cols[0],
                        "Description": cols[1]
                    })

    # --- Potential Mitigations ---
    potential_mitigations = []
    mitigation_section = get_section(soup, "Potential_Mitigations", cwe_id)
    if mitigation_section:
        table = mitigation_section.find_next("table")
        if table:
            for row in table.find_all("tr")[1:]:
                cells = row.find_all("td")
                if len(cells) >= 2:
                    phase = cells[0].get_text(" ", strip=True)
                    right_cell = cells[1]
                    strategy = None
                    effectiveness = None

                    for subheading in right_cell.find_all("p", class_="suboptheading"):
                        txt = subheading.get_text(" ", strip=True)
                        if "Strategy" in txt:
                            strategy = txt.replace("Strategy:", "").strip()
                        elif "Effectiveness" in txt:
                            effectiveness = txt.replace("Effectiveness:", "").strip()

                    description_parts = []
                    for elem in right_cell.find_all(["p", "div"], recursive=False):
                        txt = elem.get_text(" ", strip=True)
                        if txt and not any(x in txt for x in ["Strategy:", "Effectiveness:"]):
                            description_parts.append(txt)
                    mitigation_description = " ".join(description_parts).strip() or "-"

                    potential_mitigations.append({
                        "Phase": phase or "-",
                        "Strategy": strategy or "-",
                        "Effectiveness": effectiveness or "-",
                        "Description": mitigation_description
                    })

    # --- Modes of Introduction ---
    modes_of_introduction = []
    modes_section = get_section(soup, "Modes_Of_Introduction", cwe_id)
    if modes_section:
        table = modes_section.find_next("table")
        if table:
            for row in table.find_all("tr")[1:]:
                cols = [td.get_text(" ", strip=True) or "-" for td in row.find_all("td")]
                if len(cols) >= 2:
                    modes_of_introduction.append({
                        "Phase": cols[0],
                        "Note": cols[1]
                    })

    # --- Applicable Platforms ---
    applicable_platforms = {"Languages": [], "Technologies": [], "Other": []}
    platform_section = soup.find("div", {"id": "Applicable_Platforms"})
    if platform_section:
        table = platform_section.find_next("table")
        if table:
            current_category = None
            for row in table.find_all("tr"):
                cells = row.find_all("td")
                if not cells:
                    continue

                first_text = cells[0].get_text(" ", strip=True)
                if first_text.lower().startswith(("language", "technolog")):
                    current_category = "Languages" if "language" in first_text.lower() else "Technologies"
                    if len(cells) > 1:
                        value_text = cells[1].get_text(" ", strip=True)
                        if value_text:
                            applicable_platforms[current_category].append(value_text)
                    continue

                joined = " ".join(c.get_text(" ", strip=True) for c in cells if c.get_text(strip=True))
                if joined:
                    if current_category:
                        applicable_platforms[current_category].append(joined)
                    else:
                        applicable_platforms["Other"].append(joined)
        else:
            for div in platform_section.find_all("div", class_="indent"):
                txt = div.get_text(" ", strip=True)
                if txt:
                    applicable_platforms["Other"].append(txt)

    try:
        logging.info(f"Inferring CAPEC links for {cwe_id} via NLP hybrid model ")
        ranked = link_nodes(description, "CWE", "CAPEC",  limit=600, matcher = GLOBAL_MATCHER)
        capec_ids.extend([
            r["item"].get("CAPEC_ID", "?")
            for r in ranked
        ])

    except Exception as e:
        logging.warning(f"Hybrid inference failed for {cwe_id}: {e}")

    try:
        logging.info(f"Inferring CVE links for {cwe_id} via NLP hybrid model ")
        ranked = link_nodes(description, "CWE", "CVE", limit=300, matcher= GLOBAL_MATCHER)
        related_cves.extend([
            r["item"].get("CVE_ID", "?")
            for r in ranked
        ])
    except Exception as e:
        logging.warning(f"Hybrid inference failed for {cwe_id}: {e}")


    # --- Return structured result ---
    return {
        "CWE_ID": cwe_id,
        "Title": title,
        "Description": description,
        "Likelihood_of_Exploit": likelihood,
        "Common_Consequences": consequences,
        "Detection_Methods": detection_methods,
        "Mapping_Notes": mapping_notes,
        "Taxonomy_Mappings": taxonomy_mappings,
        "Weakness_Ordinality": weakness_ordinalities or "-",
        "Potential_Mitigations": potential_mitigations,
        "Modes_of_Introduction": modes_of_introduction,
        "Applicable_Platforms": applicable_platforms,
        "Memberships": memberships,
        "Relationships": relationships,
        "Related_CVEs": related_cves,
        "Related_CAPEC": capec_ids,
        "Source": base_url,
    }

