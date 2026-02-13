import xml.etree.ElementTree as ET
import sys

# ---- Allowed-only plugins ----
ALLOWED_KEYWORDS = [
    "nessus scan information",
    "syn scan",
    "traceroute"
]

def allowed_only(plugin_names):
    for p in plugin_names:
        name = p.lower()
        if not any(k in name for k in ALLOWED_KEYWORDS):
            return False
    return True


tree = ET.parse(sys.argv[1])
root = tree.getroot()

total_ips = 0
only_trace_syn = 0
more_than_two = 0
less_than_three = 0

unique_small_findings = set()

for host in root.iter('ReportHost'):
    total_ips += 1

    plugin_names = []

    for item in host.iter('ReportItem'):
        pname = item.attrib.get('pluginName', '')
        plugin_names.append(pname)

    findings_count = len(plugin_names)

    # Section 2
    if plugin_names and allowed_only(plugin_names):
        only_trace_syn += 1

    # Section 4
    if findings_count > 2:
        more_than_two += 1

    # Section 5
    if findings_count < 3:
        less_than_three += 1
        for p in plugin_names:
            unique_small_findings.add(p)

# Section 3
excluded_count = total_ips - only_trace_syn

# ---- OUTPUT ----
print("\n===== RESULTS =====")
print("1. Overall unique IPs:", total_ips)
print("2. Only scan info + traceroute:", only_trace_syn)
print("3. After excluding them:", excluded_count)
print("4. Assets with >2 findings:", more_than_two)
print("5. Assets with <3 findings:", less_than_three)

print("\n6. Unique findings on assets with <3 findings:")
for f in sorted(unique_small_findings):
    print(" -", f)
