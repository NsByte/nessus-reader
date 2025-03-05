import xml.etree.ElementTree as ET
import sys

def extract_hosts(nessus_file, plugin_name, unique=False):
    hosts = []  # List to store hosts (can contain duplicates)
    
    # Parse the Nessus XML file
    tree = ET.parse(nessus_file)
    root = tree.getroot()

    # Iterate through all report items
    for report_host in root.findall(".//ReportHost"):
        host_name = report_host.attrib["name"]

        for report_item in report_host.findall(".//ReportItem"):
            if plugin_name in report_item.attrib.get("pluginName", ""):
                hosts.append(host_name)  # Store host (including duplicates)

    # Handle unique filtering
    if unique:
        hosts = sorted(set(hosts))  # Remove duplicates

    # Print results
    print(f"Total hosts with '{plugin_name}': {len(hosts)}")
    for host in hosts:
        print(host)

# Check for command-line arguments
if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python script.py <file.nessus> '<plugin name>' [-u/--unique]")
        sys.exit(1)

    nessus_file = sys.argv[1]
    plugin_name = sys.argv[2]
    unique = "-u" in sys.argv or "--unique" in sys.argv  # Check for unique flag

    extract_hosts(nessus_file, plugin_name, unique)
