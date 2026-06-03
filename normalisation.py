import json
from rapidfuzz import process, fuzz

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