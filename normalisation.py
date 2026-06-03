import json
import xml.etree.ElementTree as ET
from pathlib import Path
from rapidfuzz import process, fuzz

# ============================================================
# DATASET PATHS
# ============================================================

_ROOT = Path(__file__).parent
DATA_DIR       = _ROOT / "dataset"
CPE_DICT_PATH  = DATA_DIR / "official-cpe-dictionary_v2.3.xml"
KEV_PATH       = DATA_DIR / "CISA-KEV" / "known_exploited_vulnerabilities.json"
NVD_2024_PATH  = DATA_DIR / "NVD-CVE" / "CVE-2024.json"
NVD_2025_PATH  = DATA_DIR / "NVD-CVE" / "CVE-2025.json"
NVD_2026_PATH  = DATA_DIR / "NVD-CVE" / "CVE-2026.json"
EPSS_DIR       = DATA_DIR / "EPSS"
EPSS_GLOB      = "epss_scores-*.csv.gz"   # use EPSS_DIR.glob(EPSS_GLOB) to find it

# ============================================================
# CPE MAP — verified from CVE-2024.json on 2026-06-03
# ============================================================

CPE_MAP = {
    # Microsoft
    "Microsoft 365 Apps for Business": ["microsoft:365_apps"],
    "Microsoft 365":                   ["microsoft:365_apps"],
    "Office 365":                      ["microsoft:365_apps"],
    "Windows 10 Pro":                  ["microsoft:windows_10_22h2", "microsoft:windows_10_21h2"],
    "Windows 10":                      ["microsoft:windows_10_22h2", "microsoft:windows_10_21h2"],
    "Windows Server 2022":             ["microsoft:windows_server_2022", "microsoft:windows_server_2022_23h2"],
    "Windows Server 2019":             ["microsoft:windows_server_2019"],

    # Adobe
    "Adobe Acrobat Reader DC":         ["adobe:acrobat_reader_dc", "adobe:acrobat_reader", "adobe:acrobat_dc"],
    "Adobe Acrobat Reader":            ["adobe:acrobat_reader_dc", "adobe:acrobat_reader", "adobe:acrobat_dc"],

    # Cisco
    "Cisco IOS XE":                    ["cisco:ios_xe"],

    # VMware
    "VMware vSphere":                  ["vmware:vcenter_server", "vmware:workstation"],
    "vSphere":                         ["vmware:vcenter_server", "vmware:workstation"],

    # Google
    "Google Chrome":                   ["google:chrome"],
    "Chrome":                          ["google:chrome"],

    # OpenSSL
    "OpenSSL":                         ["openssl:openssl"],

    # Apache
    "Apache HTTP Server":              ["apache:http_server"],
    "Apache":                          ["apache:http_server"],

    # Zoom
    "Zoom":                            ["zoom:zoom", "zoom:rooms_controller"],

    # WordPress
    "WordPress":                       ["wordpress:wordpress"],

    # Moodle
    "Moodle":                          ["moodle:moodle"],
}


# ============================================================
# CPE DICTIONARY LOADER
# Parses official-cpe-dictionary_v2.3.xml into a title→cpe_string
# index that extends CPE_MAP when the file is present.
# ============================================================

_CPE_NS = "{http://cpe.mitre.org/dictionary/2.0}"
_XML_NS  = "{http://www.w3.org/XML/1998/namespace}"


def load_cpe_dictionary(path: Path = CPE_DICT_PATH) -> dict[str, list[str]]:
    """
    Parse the official CPE 2.3 dictionary XML and return a dict of
    { normalised_title: [cpe_vendor:product, ...] }.
    Returns an empty dict if the file is not present.
    """
    if not path.exists():
        print(f"  CPE dictionary not found at {path} — using hardcoded CPE_MAP only")
        return {}

    print(f"  Loading CPE dictionary from {path} …")
    title_map: dict[str, list[str]] = {}

    for _, elem in ET.iterparse(path, events=("end",)):
        if elem.tag != f"{_CPE_NS}cpe-item":
            continue

        cpe_name = elem.get("name", "")
        # cpe:2.3:a:vendor:product:... → keep vendor:product
        parts = cpe_name.split(":")
        if len(parts) >= 5:
            vp = f"{parts[3]}:{parts[4]}"
        else:
            elem.clear()
            continue

        # Prefer the English title element
        for title_el in elem.findall(f"{_CPE_NS}title"):
            if title_el.get(f"{_XML_NS}lang", "en-US") == "en-US":
                title = (title_el.text or "").strip()
                if title:
                    title_map.setdefault(title, [])
                    if vp not in title_map[title]:
                        title_map[title].append(vp)
                break

        elem.clear()  # free memory as we stream

    print(f"  Loaded {len(title_map):,} CPE titles from dictionary")
    return title_map


def build_extended_map(cpe_dict_path: Path = CPE_DICT_PATH) -> dict[str, list[str]]:
    """Merge the hardcoded CPE_MAP with entries from the official dictionary."""
    extended = dict(CPE_MAP)
    for title, cpes in load_cpe_dictionary(cpe_dict_path).items():
        if title not in extended:
            extended[title] = cpes
    return extended


# ============================================================
# NORMALISE FUNCTION
# ============================================================

def normalise(asset_name):
    """
    Takes an informal asset name string.
    Returns a list of verified CPE vendor:product strings.
    Returns empty list if no confident match found.
    """
    # Step 1: exact match
    if asset_name in CPE_MAP:
        return CPE_MAP[asset_name]

    # Step 2: fuzzy match
    result = process.extractOne(
        asset_name,
        CPE_MAP.keys(),
        scorer=fuzz.WRatio,
        score_cutoff=70
    )

    if result:
        matched_key, score, _ = result
        print(f"  Fuzzy matched '{asset_name}' → '{matched_key}' (confidence: {score:.0f}%)")
        return CPE_MAP[matched_key]
    else:
        print(f"  WARNING: No CPE match found for '{asset_name}'")
        return []


# ============================================================
# TEST — run this file directly to verify everything works
# python normalisation.py
# ============================================================

if __name__ == "__main__":
    sample_assets = [
        "Microsoft 365 Apps for Business",
        "Windows Server 2022",
        "Windows 10 Pro",
        "Adobe Acrobat Reader DC",
        "Cisco IOS XE",
        "VMware vSphere",
        "Google Chrome",
        "OpenSSL",
        "Apache HTTP Server",
        "Zoom",
        "WordPress",
        "Moodle",
    ]

    print("=== Normalisation Test ===\n")
    for asset in sample_assets:
        cpes = normalise(asset)
        print(f"  {asset:40s} → {cpes}")