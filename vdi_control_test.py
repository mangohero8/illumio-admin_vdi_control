# illumio_ruleset_export_Admin_VDI.py
# -----------------------------------
# This script exports Illumio ruleset data to CSV/Excel for audit and control testing.
# It fetches rulesets, labels, label groups, IP lists, and services from the Illumio API,
# processes the rules, and outputs a detailed, filterable spreadsheet for review.
#
# Steps:
# 1. Fetch all required data from Illumio API endpoints.
# 2. Build lookup maps for labels, label groups, IP lists, and services.
# 3. Iterate through all rulesets and rules, mapping sources/destinations as per Illumio UI.
# 4. Apply filters and output to CSV and Excel, with audit decision columns.
# 5. Write rules with blank sources/destinations to a separate JSON for further review.
# 6. Provide post-processing for audit evidence and optional filtering.


import requests  # For API calls
import csv       # For CSV writing
import logging   # For logging steps and errors
from requests.auth import HTTPBasicAuth
import os        # For file path handling
import urllib3   # For disabling SSL warnings
import time      # For timestamped output
import re        # For regex operations
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- LOGGING SETUP ---
logging.basicConfig(
    filename=f'illumio_admin_vdi_log_{time.strftime("%d-%m-%Y")}.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logging.info('Script started.')


# --- CONFIGURATION ---
# Update these with your Illumio API details
API_USER = ""  # API username
API_KEY = ""  # API key/secret
FQDN = "us-scp14.illum.io"  # Illumio PCE FQDN
PORT = "443"                # API port
ORG_ID = "3801148"          # Organization ID


# Construct base API URL
BASE_URL = f"https://{FQDN}:{PORT}/api/v2/orgs/{ORG_ID}"
# Output CSV file with timestamp
OUTPUT_CSV = os.path.join(os.path.dirname(__file__), f"Admin_VDI_NonCompliantRules_{time.strftime('%d-%m-%Y')}.csv")
# Restricted ports for control test (TCP/UDP)
RESTRICTED_PORTS = {"22", "23", "3389", "7389"}
# For Excel post-processing
import pandas as pd


# --- API ENDPOINTS ---
RULESETS_URL = f"{BASE_URL}/sec_policy/active/rule_sets?max_results=100000"  # All active rulesets
LABELS_URL = f"{BASE_URL}/labels?max_results=100000"                         # All labels
LABEL_GROUPS_URL = f"{BASE_URL}/sec_policy/draft/label_groups?max_results=100000"  # All label groups
IP_LISTS_URL = f"{BASE_URL}/sec_policy/draft/ip_lists?max_results=100000"    # All IP lists
SERVICES_URL = f"{BASE_URL}/sec_policy/active/services?max_results=100000"   # All services


# --- HELPER FUNCTIONS ---
def fetch_items(url):
    """
    Fetch items from a given Illumio API endpoint.
    Returns a list of items (dicts).
    """
    logging.info(f'Fetching items from URL: {url}')
    try:
        resp = requests.get(url, verify=False, headers={"Accept": "application/json"}, auth=HTTPBasicAuth(API_USER, API_KEY))
        resp.raise_for_status()
        items = resp.json()
        if isinstance(items, dict) and "items" in items:
            items = items["items"]
        logging.info(f'Successfully fetched {len(items)} items from {url}')
        return items
    except requests.exceptions.RequestException as e:
        logging.error(f'Error fetching items from {url}: {e}')
        raise

# Build a map of label hrefs to label values (for quick lookup)
def get_label_map():
    logging.info('Building label map...')
    labels = fetch_items(LABELS_URL)
    allowed_prefixes = ("A-", "R-", "E-", "L-")
    def allowed(label):
        return any(label.startswith(p) for p in allowed_prefixes)
    label_map = {}
    for label in labels:
        val = label.get('value', '')
        if allowed(val):
            label_map[label['href']] = val
    return label_map
# Build a mapping from label value to label group names
def get_label_group_map():
    logging.info('Building label group map...')
    label_groups = fetch_items(LABEL_GROUPS_URL)
    label_value_to_groups = {}
    for lg in label_groups:
        group_name = lg.get('name', '')
        for lbl in lg.get('labels', []):
            val = lbl.get('value', '')
            if val:
                label_value_to_groups.setdefault(val, set()).add(group_name)
    return label_value_to_groups

# Build a map of IP list hrefs to names (handles both draft and active hrefs)
def get_ip_list_map():
    logging.info('Building IP list map...')
    ip_lists = fetch_items(IP_LISTS_URL)
    ip_list_map = {}
    for ip in ip_lists:
        href = ip['href']
        name = ip.get('name', '')
        ip_list_map[href] = name
        # Map both draft and active hrefs to the same name
        if '/draft/ip_lists/' in href:
            active_href = href.replace('/draft/ip_lists/', '/active/ip_lists/')
            ip_list_map[active_href] = name
    return ip_list_map

# Build a map of service hrefs to service details (name, ports)
def get_service_map():
    logging.info('Building service map...')
    services = fetch_items(SERVICES_URL)
    service_map = {}
    for svc in services:
        name = svc.get('name', '')
        ports = []
        for sp in svc.get('service_ports', []):
            # If port range, output as 'port-to_port'
            if 'port' in sp and 'to_port' in sp:
                ports.append(f"{int(sp['port'])}-{int(sp['to_port'])}")
            elif 'port' in sp:
                ports.append(str(int(sp['port'])))
        service_map[svc['href']] = {
            'name': name,
            'ports': ports
        }
    return service_map

# Fetch all rulesets
def get_rulesets():
    logging.info('Fetching all rulesets...')
    return fetch_items(RULESETS_URL)


def main():
    # --- MAIN SCRIPT LOGIC ---
    # Build lookup maps for all resources
    logging.info('Starting main export process.')
    label_map = get_label_map()  # href -> label value
    label_value_to_groups = get_label_group_map()  # label value -> label group names
    ip_list_map = get_ip_list_map()  # href -> IP list name
    service_map = get_service_map()  # href -> service details
    rulesets = get_rulesets()  # All rulesets

    blank_rules = []  # Track rules with blank sources/destinations
    disabled_over_30_hrefs = []  # Track rules disabled >30 days (future use)
    all_rows = []  # All output rows
    # Output header for CSV/Excel
    header = ['Policy', 'Scopes', 'Sources', 'Source Label Groups', 'Destinations', 'Destination Label Groups', 'Destination Services', 'Ruleset Enabled', 'Disabled >30 Days', 'Rule HREF']
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
        writer.writerow(header)
        for ruleset in rulesets:
            policy_name = ruleset.get('name', '')
            scopes = ruleset.get('scopes', [])
            scopes_flat = []
            # Flatten all scope label values
            for scope_group in scopes:
                for scope in scope_group:
                    label = scope.get('label', {})
                    label_href = label.get('href', '') if label else ''
                    label_val = label_map.get(label_href, '') if label_href else ''
                    if label_val:
                        scopes_flat.append(label_val)
            scopes_str = '; '.join(scopes_flat)
            rules = ruleset.get('rules', [])
            logging.info(f'Processing ruleset: {policy_name} with {len(rules)} rules.')
            for rule in rules:
                # SWAP: consumers = Sources, providers = Destinations (to match Illumio UI)
                sources_flat = []
                source_label_groups = set()
                for src in rule.get('consumers', []):
                    # Handle actors, IP lists, labels, and label groups for sources
                    if 'actors' in src:
                        if src['actors'] == 'ams':
                            sources_flat.append('All Workloads')
                            logging.info('Rule source includes All Workloads (ams).')
                        else:
                            sources_flat.append(f"actors:{src['actors']}")
                    if 'ip_list' in src:
                        ip_href = src['ip_list'].get('href','')
                        ip_name = ip_list_map.get(ip_href, '')
                        if ip_name:
                            sources_flat.append(ip_name)
                        elif ip_href:
                            sources_flat.append(ip_href)
                    if 'label' in src:
                        label_obj = src['label']
                        label_href = label_obj.get('href','') if label_obj else ''
                        label_val = label_map.get(label_href, '') if label_href else ''
                        if label_val:
                            sources_flat.append(label_val)
                            for group in label_value_to_groups.get(label_val, []):
                                source_label_groups.add(group)
                    if 'label_group' in src:
                        pass
                sources_str = '; '.join(sources_flat)
                source_label_groups_str = '; '.join(sorted(source_label_groups))

                destinations_flat = []
                dest_label_groups = set()
                for dst in rule.get('providers', []):
                    if 'actors' in dst and dst['actors'] != 'ams':
                        destinations_flat.append(f"actors:{dst['actors']}")
                    if 'ip_list' in dst:
                        ip_href = dst['ip_list'].get('href','')
                        ip_name = ip_list_map.get(ip_href, '')
                        if ip_name:
                            destinations_flat.append(ip_name)
                        elif ip_href:
                            destinations_flat.append(ip_href)
                    if 'label' in dst:
                        label_obj = dst['label']
                        label_href = label_obj.get('href','') if label_obj else ''
                        label_val = label_map.get(label_href, '') if label_href else ''
                        if label_val:
                            destinations_flat.append(label_val)
                            for group in label_value_to_groups.get(label_val, []):
                                dest_label_groups.add(group)
                    if 'label_group' in dst:
                        pass
                destinations_str = '; '.join(destinations_flat)
                dest_label_groups_str = '; '.join(sorted(dest_label_groups))

                services_flat = []
                for svc in rule.get('ingress_services', []):
                    svc_info = service_map.get(svc.get('href', ''), None)
                    if svc_info:
                        if any(port in RESTRICTED_PORTS for port in svc_info.get('ports', [])):
                            services_flat.append(svc_info['name'])
                    else:
                        continue
                services_str = '; '.join(services_flat)

                if not sources_str or not destinations_str:
                    blank_rules.append({
                        'policy_name': policy_name,
                        'scopes': scopes_str,
                        'rule': rule
                    })
                    logging.warning(f'Rule with blank sources or destinations in ruleset: {policy_name}')
                enabled = rule.get('enabled')
                if enabled is None:
                    enabled = ruleset.get('enabled')

                # --- FILTERS BEGIN ---
                if not enabled:
                    logging.info('Rule skipped: not enabled.')
                    continue
                if not services_flat:
                    logging.info('Rule skipped: no restricted services.')
                    continue
                if 'E-PD' not in scopes_str:
                    logging.info('Rule skipped: not in E-PD scope.')
                    continue
                source_exclude_patterns = [
                    'A-', 'E-',
                    'IPL-ADMIN_VDI', 'IPL-CLUSTER_LINK_LOCAL',
                    'IPL-MAINFRAME_', 'IPL-GUARDIUM-100028',
                    'IPL-IPT_VOICE_INFRASTRUCTURE_CORE_DATA_CENTER_NETWORKS',
                    'IPL-LOAD_BALANCERS'
                ]
                if any(pat in sources_str for pat in source_exclude_patterns):
                    logging.info('Rule skipped: source matches exclude pattern.')
                    continue
                if 'IPL-ADMIN_VDI' in destinations_str:
                    logging.info('Rule skipped: destination matches exclude pattern.')
                    continue
                # --- FILTERS END ---

                disabled_over_30 = ""
                rule_href = rule.get('href', '')
                row = [policy_name, scopes_str, sources_str, source_label_groups_str, destinations_str, dest_label_groups_str, services_str, str(enabled), disabled_over_30, rule_href]
                all_rows.append(row)
                writer.writerow(row)
                logging.info(f'Exported rule: {rule_href}')

    # Write rules with blank sources or destinations to a separate JSON file for audit review

    if blank_rules:
        import json
        blank_json_path = os.path.join(os.path.dirname(__file__), "illumio_blank_rules.json")
        with open(blank_json_path, 'w', encoding='utf-8') as jf:
            json.dump(blank_rules, jf, indent=2)
        print(f"Wrote rules with blank sources or destinations to {blank_json_path}")
        logging.info(f'Wrote rules with blank sources or destinations to {blank_json_path}')

    print(f"Exported enriched active rulesets to {OUTPUT_CSV}")
    logging.info(f'Exported enriched active rulesets to {OUTPUT_CSV}')

    # --- POST-PROCESSING: Excel Filtering and Audit Evidence ---
    # This section adds audit columns and decision filters to the Excel output
    print("\n--- Post-processing for Audit Evidence ---")
    logging.info('Starting post-processing for audit evidence.')
    target_cis = input("Enter Target CIs (comma-separated, or leave blank to skip): ").strip()
    target_cis_list = [ci.strip() for ci in target_cis.split(",") if ci.strip()] if target_cis else []

    try:
        df = pd.read_csv(OUTPUT_CSV)
    except Exception as e:
        logging.error(f'Error reading output CSV for post-processing: {e}')
        raise
    df['Audit CIs'] = ''
    if target_cis_list:
        for ci in target_cis_list:
            df.loc[df['Scopes'].str.contains(ci, na=False), 'Audit CIs'] = ci

    # Insert 'Decision Filters' column after 'Sources'
    insert_at = df.columns.get_loc('Sources') + 1
    df.insert(insert_at, 'Decision Filters', '')

    # Apply audit decision logic for each rule
    df.loc[df['Sources'].isna() | (df['Sources'] == ''), 'Decision Filters'] = 'Exclude – No Remaining Sources With Access'
    df.loc[df['Sources'].str.contains(r'A-END_USER_COMPUTE_\(EUC\)', na=False), 'Decision Filters'] = 'Keep for Review - contains A-END_USER_COMPUTE_(EUC)'
    df.loc[(df['Decision Filters'] == '') & df['Sources'].str.contains('IPL-', na=False), 'Decision Filters'] = 'Keep for Review – contains an IP List'
    df.loc[(df['Decision Filters'] == '') & df['Sources'].str.contains('A-', na=False), 'Decision Filters'] = 'Exclude - Application to Application Traffic is Permitted'
    df.loc[df['Decision Filters'] == '', 'Decision Filters'] = 'Needs Review'

    # Write final Excel file for audit evidence
    excel_path = OUTPUT_CSV.replace('.csv', '_audit.xlsx')
    try:
        df.to_excel(excel_path, index=False)
        print(f"Audit evidence Excel file written to {excel_path}")
        logging.info(f'Audit evidence Excel file written to {excel_path}')
    except Exception as e:
        logging.error(f'Error writing Excel file: {e}')
        raise

    # Optional: Filter out rules disabled >30 days (future logic placeholder)
    if disabled_over_30_hrefs:
        print("\nThe following rules have been disabled for more than 30 days:")
        for href in disabled_over_30_hrefs:
            print(href)
        confirm = input("\nDo you want to create a filtered CSV excluding these rules? (y/N): ").strip().lower()
        if confirm == 'y':
            filtered_rows = [row for row in all_rows if not (row[8] == "TRUE" and row[9])]
            filtered_csv = OUTPUT_CSV.replace('.csv', '_filtered.csv')
            try:
                with open(filtered_csv, 'w', newline='', encoding='utf-8') as fcsv:
                    writer = csv.writer(fcsv, quoting=csv.QUOTE_ALL)
                    writer.writerow(header)
                    for row in filtered_rows:
                        writer.writerow(row)
                print(f"Filtered CSV (excluding rules disabled >30 days) written to: {filtered_csv}")
                logging.info(f'Filtered CSV (excluding rules disabled >30 days) written to: {filtered_csv}')
            except Exception as e:
                logging.error(f'Error writing filtered CSV: {e}')
                raise
        else:
            print("No filtered CSV was created.")
            logging.info('No filtered CSV was created.')


# Entry point
if __name__ == "__main__":
    try:
        main()
        logging.info('Script completed successfully.')
    except Exception as e:
        logging.error(f'Unhandled exception in script: {e}')
