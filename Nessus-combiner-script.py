import xml.etree.ElementTree as etree
import os

# 1. Initialize
mainTree = None
report = None
existing_hosts_map = {} # This is the speed booster

for fileName in os.listdir("."):
    if fileName.endswith(".nessus"):
        print("Processing:", fileName)
        tree = etree.parse(fileName)
        current_report = tree.find('Report')

        if mainTree is None:
            # First file setup
            mainTree = tree
            report = mainTree.find('Report')
            report.attrib['name'] = 'Combined final'
            # Map existing hosts in the first file
            for host in report.findall('ReportHost'):
                existing_hosts_map[host.attrib['name']] = host
        else:
            # Merge subsequent files
            for host in current_report.findall('ReportHost'):
                host_name = host.attrib['name']
                
                if host_name not in existing_hosts_map:
                    # New host, just add it
                    report.append(host)
                    existing_hosts_map[host_name] = host
                else:
                    # Host exists, merge items (vulnerabilities)
                    existing_host = existing_hosts_map[host_name]
                    
                    # Create a set of unique IDs for items already in this host
                    # Format: (port, pluginID)
                    seen_items = { (item.attrib['port'], item.attrib['pluginID']) 
                                   for item in existing_host.findall('ReportItem') }

                    for item in host.findall('ReportItem'):
                        item_key = (item.attrib['port'], item.attrib['pluginID'])
                        if item_key not in seen_items:
                            existing_host.append(item)
                            seen_items.add(item_key)

if mainTree:
    print("Saving combined file...")
    mainTree.write("Combined_final.nessus", encoding="utf-8", xml_declaration=True)
    print("Done!")