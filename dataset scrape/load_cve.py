
import json


with open('data/CVE-2024.json') as f:
    cve_data = json.load(f)

records = cve_data['cve_items']  # this is confirmed correct for your file
print(f"Total CVEs in 2024 file: {len(records)}")
print("First record keys:", records[0].keys())

one = records[0]
print(json.dumps(one, indent=2)[:3000])


# 1. CVE ID
print("ID:", one['id'])

# 2. English description
descs = one.get('descriptions', [])
english = next((d['value'] for d in descs if d['lang'] == 'en'), 'No description')
print("Description:", english[:200])

# 3. CVSS score
metrics = one.get('metrics', {})
if 'cvssMetricV31' in metrics:
    score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
elif 'cvssMetricV30' in metrics:
    score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
else:
    score = None
print("CVSS:", score)


# Corrected CPE extraction - note the extra nodes loop
configs = one.get('configurations', [])
cpe_strings = []
for node in configs:
    for subnode in node.get('nodes', []):        # <- this level was missing
        for match in subnode.get('cpeMatch', []):
            cpe_strings.append(match['criteria'])
print("CPE strings:", cpe_strings[:3])


found = 0
for record in records:
    cpe_strings = []
    for node in record.get('configurations', []):
        for subnode in node.get('nodes', []):
            for match in subnode.get('cpeMatch', []):
                cpe_strings.append(match['criteria'])
    
    if cpe_strings:
        print("ID:", record['id'])
        print("CPE strings:", cpe_strings[:3])
        print("---")
        found += 1
        if found == 5:
            break


# === HOUR 2: Find real CPE strings from your CVE data ===

def find_cpe_strings(keyword, records, max_results=10):
    found = set()
    for record in records:
        for node in record.get('configurations', []):
            for subnode in node.get('nodes', []):
                for match in subnode.get('cpeMatch', []):
                    criteria = match['criteria']
                    if keyword.lower() in criteria.lower():
                        parts = criteria.split(':')
                        if len(parts) >= 5:
                            found.add(f"{parts[3]}:{parts[4]}")
    return list(found)[:max_results]

# Search for all 12 sample assets
searches = [
    "openssl",
    "apache",
    "wordpress",
    "moodle",
    "chrome",
    "cisco",
    "zoom",
    "vmware",
    "adobe",
    "windows_10",
    "windows_server",
    "365_apps",
]

print("=== CPE strings found in CVE-2024.json ===\n")
for term in searches:
    results = find_cpe_strings(term, records)
    print(f"{term:20s} → {results}")

# Fill the gaps with targeted searches
gaps = [
    "acrobat_reader",
    "acrobat_dc", 
    "ios_xe",
    "http_server",
    "windows_server_2022",
]

print("=== Targeted searches ===\n")
for term in gaps:
    results = find_cpe_strings(term, records)
    print(f"{term:25s} → {results}")