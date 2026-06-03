CVE Translator — Normalisation Stage (Hour 2)
What normalisation is
The user types informal software names like "Microsoft 365 Apps for Business". The CVE
database uses structured CPE identifiers like microsoft:365_apps. Normalisation is the
process of bridging that gap.
This is the hardest and most important step. A wrong mapping does not produce an
error — it just silently returns zero CVEs for that product. There is no warning. There is
just a missed result.

The structure of a CPE string
Every CPE string looks like this:
cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*
              ^        ^      ^
           vendor   product  version
          index[3] index[4] index[5]
Split on : and you get:

Index 3 = vendor (e.g. openssl, microsoft, apache)
Index 4 = product (e.g. openssl, windows_10, http_server)

Your matcher only needs vendor:product — the version is handled separately.

The CPE mapping dictionary
This maps informal names to their confirmed CPE vendor:product strings.
Values are lists because some products map to multiple CPEs (e.g. VMware vSphere).
pythonCPE_MAP = {
    "Microsoft 365":           ["microsoft:365_apps"],
    "Office 365":              ["microsoft:365_apps"],
    "Windows Server 2022":     ["microsoft:windows_server_2022"],
    "Windows Server 2019":     ["microsoft:windows_server_2019"],
    "Windows 10":              ["microsoft:windows_10", "microsoft:windows_10_22h2"],
    "Windows 10 Pro":          ["microsoft:windows_10", "microsoft:windows_10_22h2"],
    "Adobe Acrobat Reader":    ["adobe:acrobat_reader_dc", "adobe:acrobat_dc", "adobe:acrobat_reader"],
    "Adobe Acrobat Reader DC": ["adobe:acrobat_reader_dc", "adobe:acrobat_dc", "adobe:acrobat_reader"],
    "Cisco IOS XE":            ["cisco:ios_xe"],
    "VMware vSphere":          ["vmware:vcenter_server", "vmware:esxi"],
    "vSphere":                 ["vmware:vcenter_server", "vmware:esxi"],
    "Google Chrome":           ["google:chrome"],
    "Chrome":                  ["google:chrome"],
    "OpenSSL":                 ["openssl:openssl"],
    "Apache HTTP Server":      ["apache:http_server"],
    "Apache":                  ["apache:http_server"],
    "Zoom":                    ["zoom:zoom", "zoom:meetings", "zoom:zoom_client"],
    "WordPress":               ["wordpress:wordpress"],
    "Moodle":                  ["moodle:moodle"],
}
Tricky cases to know for the demo
Asset nameProblemCPE solutionVMware vSpherevSphere is a suite, not one productMaps to both vmware:vcenter_server AND vmware:esxiAdobe Acrobat Reader DCFragmented across 3 CPE names across yearsMap all three variantsWindows 10 Pro 22H2Newer records use version-specific CPEMap both windows_10 and windows_10_22h2ZoomProduct name varies by yearMap zoom:zoom, zoom:meetings, zoom:zoom_clientMicrosoft 365 Apps for BusinessVery informal nameStrip to core → microsoft:365_apps

The normalise() function
Takes an informal asset name, tries an exact match first, then falls back to fuzzy matching.
pythonfrom rapidfuzz import process, fuzz

def normalise(asset_name):
    """
    Takes an informal asset name.
    Returns a list of CPE vendor:product strings.
    Returns empty list if no confident match found.
    """
    # Step 1: exact match
    if asset_name in CPE_MAP:
        return CPE_MAP[asset_name]

    # Step 2: fuzzy match against dictionary keys
    result = process.extractOne(
        asset_name,
        CPE_MAP.keys(),
        scorer=fuzz.WRatio,
        score_cutoff=70  # below 70% confidence, reject
    )

    if result:
        matched_key, score, _ = result
        print(f"  Fuzzy matched '{asset_name}' → '{matched_key}' (confidence: {score:.0f}%)")
        return CPE_MAP[matched_key]
    else:
        print(f"  WARNING: No CPE match found for '{asset_name}'")
        return []

How to test it
Run this against the full sample asset list before building anything else.
Do not proceed to the matcher until 10 of 12 assets resolve correctly.
pythonsample_assets = [
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
    print(f"  {asset:40s} → {cpes}\n")
What good output looks like
Every asset should resolve to at least one CPE string. No WARNING lines.
Example of a correct result:
  OpenSSL                                  → ['openssl:openssl']
  VMware vSphere                           → ['vmware:vcenter_server', 'vmware:esxi']
  Adobe Acrobat Reader DC                  → ['adobe:acrobat_reader_dc', 'adobe:acrobat_dc', 'adobe:acrobat_reader']

How to verify CPE strings
If you are unsure about a CPE string, grep the actual CVE data to confirm it exists:
python# Confirm a CPE string actually appears in your CVE dataset
target = "openssl:openssl"
matches = []
for record in records:
    for node in record.get('configurations', []):
        for subnode in node.get('nodes', []):
            for match in subnode.get('cpeMatch', []):
                if target in match['criteria']:
                    matches.append(record['id'])
                    break

print(f"Found {len(matches)} CVEs referencing '{target}'")
print("Sample:", matches[:3])
If this returns 0, the CPE string is wrong. Adjust the dictionary before continuing.

Key things to say in the demo

Why this is hard: the user types "Office 365 Business" but the CPE is microsoft:365_apps.
There is no error when the mapping is wrong — just a silent miss.
VMware vSphere is a suite, so one asset name maps to two separate CPEs.
Adobe fragments across three different CPE product names depending on the CVE year.
A fuzzy match score below 70% is rejected to avoid false positives — better to warn than
to silently match the wrong product.


Definition of done for Hour 2

 CPE_MAP dictionary has at least 15 entries
 All 12 sample assets resolve without WARNING
 VMware and Adobe multi-CPE cases are handled
 At least one CPE string verified by grepping the actual CVE data
 normalise() function tested and working