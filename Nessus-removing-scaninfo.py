import xml.etree.ElementTree as ET
import sys

INPUT = sys.argv[1]
OUTPUT = sys.argv[2]

# Strict allowed plugin IDs
ALLOWED_IDS = {"19506", "10287", "11219"}

tree = ET.parse(INPUT)
root = tree.getroot()
report = root.find('.//Report')

removed = 0
kept = 0

hosts = list(report.findall('ReportHost'))

for host in hosts:
    plugin_ids = set()

    for item in host.iter('ReportItem'):
        pid = item.attrib.get('pluginID')
        if pid:
            plugin_ids.add(pid)

    # STRICT condition
    if plugin_ids and plugin_ids.issubset(ALLOWED_IDS):
        report.remove(host)
        removed += 1
    else:
        kept += 1

tree.write(OUTPUT, encoding="utf-8", xml_declaration=True)

print("\n===== STRICT CLEAN COMPLETE =====")
print("Removed hosts:", removed)
print("Remaining hosts:", kept)
print("Saved to:", OUTPUT)
