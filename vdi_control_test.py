#!/usr/bin/env python3
"""
Illumio Admin VDI Control Test — Automated Compliance Scanner
Control: MON.C9.9 - Admin VDI Restrictions

Automates the manual control test procedure for identifying non-compliant
admin VDI rules in Illumio PCE. Scans Production extra-scope rulesets for
rules allowing traffic over administrative ports from non-permitted sources.

Decision Filter Chain (mirrors manual guide):
  Step 1: Remove non-end-user policy objects (permitted IPLs/labels)
  Step 2: Flag rules with no remaining sources as EXCLUDED
  Step 3: Flag A-END_USER_COMPUTE_[EUC] sources for MANUAL REVIEW
  Step 4: Flag remaining IPL- sources for MANUAL REVIEW
  Step 5: Exclude app-to-app (A- to A-) traffic as PERMITTED
  Step 6: Check edge cases (env label groups applying broadly)
  Step 7: Remaining rules = NON-COMPLIANT

Outputs: Excel report with Audit Summary, Non-Compliant, Requires Review,
         Compliant/Excluded, and Execution Log sheets.

Version: 2.0.0
Author: Cybersecurity Tech Ops — Illuminati Team
"""

__version__ = "2.0.0"

import os
import sys
import csv
import hashlib
import getpass
import logging
import platform
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
import requests
from requests.auth import HTTPBasicAuth
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# CONSTANTS
# =============================================================================

CONTROL_ID = "MON.C9.9"
CONTROL_NAME = "Admin VDI Restrictions"
DEFAULT_CONFIG_PATH = "config.yaml"

# Decision Filter categories
DECISION_EXCLUDE_NO_SOURCES = "Exclude – No Remaining Sources With Access"
DECISION_EXCLUDE_APP_TO_APP = "Exclude – Application to Application Traffic is Permitted"
DECISION_EXCLUDE_PERMITTED_SOURCE = "Exclude – All Sources Are Permitted Policy Objects"
DECISION_REVIEW_EUC = "Keep for Review – Contains A-END_USER_COMPUTE_[EUC]"
DECISION_REVIEW_IPL = "Keep for Review – Contains an IP List"
DECISION_REVIEW_EDGE_CASE = "Keep for Review – Edge Case (Environment/Label Group Only)"
DECISION_NON_COMPLIANT = "Non-Compliant – Unpermitted Source on Restricted Port"


# =============================================================================
# CONFIGURATION
# =============================================================================

def load_config(config_path: str = DEFAULT_CONFIG_PATH) -> dict:
    """
    Load configuration from YAML with environment variable overrides.

    Env var precedence:
        ILLUMIO_API_USER, ILLUMIO_API_KEY, ILLUMIO_FQDN,
        ILLUMIO_PORT, ILLUMIO_ORG_ID
    """
    config = {}
    config_file = Path(config_path)
    if config_file.exists():
        with open(config_file, "r") as f:
            config = yaml.safe_load(f) or {}
        logging.info(f"Loaded configuration from {config_path}")
    else:
        logging.warning(f"Config file not found: {config_path}. Using env vars only.")

    pce = config.get("pce", {})
    config["_pce"] = {
        "fqdn": os.environ.get("ILLUMIO_FQDN", pce.get("fqdn", "")),
        "port": os.environ.get("ILLUMIO_PORT", str(pce.get("port", "8443"))),
        "org_id": os.environ.get("ILLUMIO_ORG_ID", str(pce.get("org_id", "1"))),
        "api_user": os.environ.get("ILLUMIO_API_USER", pce.get("api_user", "")),
        "api_key": os.environ.get("ILLUMIO_API_KEY", pce.get("api_key", "")),
    }

    missing = [k for k, v in config["_pce"].items()
               if not v and k in ("fqdn", "api_user", "api_key")]
    if missing:
        raise ValueError(
            f"Missing required PCE config: {', '.join(missing)}. "
            f"Set via config.yaml or environment variables."
        )

    return config


# =============================================================================
# LOGGING
# =============================================================================

class LogCapture(logging.Handler):
    """Captures log records for embedding in the Excel report."""

    def __init__(self):
        super().__init__()
        self.records: list[dict] = []

    def emit(self, record):
        self.records.append({
            "timestamp": datetime.fromtimestamp(record.created).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "level": record.levelname,
            "message": self.format(record),
        })


def setup_logging(log_file: str = "vdi_control_test.log") -> LogCapture:
    """Configure file, console, and capture logging handlers."""
    log_capture = LogCapture()
    log_capture.setLevel(logging.DEBUG)
    log_capture.setFormatter(logging.Formatter("%(message)s"))

    file_handler = logging.FileHandler(log_file, mode="a")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(file_handler)
    root.addHandler(console_handler)
    root.addHandler(log_capture)

    return log_capture


# =============================================================================
# ILLUMIO API CLIENT
# =============================================================================

class IllumioAPIClient:
    """REST client for Illumio PCE API v2."""

    def __init__(self, fqdn, port, org_id, api_user, api_key):
        self.base_url = f"https://{fqdn}:{port}/api/v2/orgs/{org_id}"
        self.auth = HTTPBasicAuth(api_user, api_key)
        self.session = requests.Session()
        self.session.verify = False
        self.session.auth = self.auth
        self.session.headers.update({"Accept": "application/json"})
        self.fqdn = fqdn
        self.org_id = org_id

    def _get(self, endpoint: str, params: Optional[dict] = None) -> list | dict:
        """GET with retry logic (3 attempts)."""
        url = f"{self.base_url}{endpoint}"
        for attempt in range(1, 4):
            try:
                logging.debug(f"API GET {url} (attempt {attempt}/3)")
                resp = self.session.get(url, params=params, timeout=60)
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.HTTPError as e:
                logging.error(f"HTTP {resp.status_code} on {url}: {e}")
                if attempt == 3:
                    raise
            except requests.exceptions.ConnectionError as e:
                logging.error(f"Connection error on {url}: {e}")
                if attempt == 3:
                    raise
            except requests.exceptions.Timeout:
                logging.warning(f"Timeout on {url}, retrying...")
                if attempt == 3:
                    raise

    def get_services(self) -> list:
        logging.info("Fetching active services...")
        result = self._get("/sec_policy/active/services")
        items = result if isinstance(result, list) else result.get("items", [])
        logging.info(f"Retrieved {len(items)} services")
        return items

    def get_rulesets(self, params: Optional[dict] = None) -> list:
        logging.info("Fetching active rulesets...")
        result = self._get("/sec_policy/active/rule_sets", params=params)
        items = result if isinstance(result, list) else result.get("items", [])
        logging.info(f"Retrieved {len(items)} rulesets")
        return items

    def get_ip_lists(self) -> list:
        logging.info("Fetching IP lists...")
        result = self._get("/sec_policy/active/ip_lists")
        items = result if isinstance(result, list) else result.get("items", [])
        logging.info(f"Retrieved {len(items)} IP lists")
        return items

    def get_labels(self) -> list:
        logging.info("Fetching labels...")
        result = self._get("/labels")
        items = result if isinstance(result, list) else result.get("items", [])
        logging.info(f"Retrieved {len(items)} labels")
        return items

    def get_label_groups(self) -> list:
        logging.info("Fetching label groups...")
        result = self._get("/sec_policy/active/label_groups")
        items = result if isinstance(result, list) else result.get("items", [])
        logging.info(f"Retrieved {len(items)} label groups")
        return items


# =============================================================================
# SERVICE RESOLUTION
# =============================================================================

def identify_restricted_services(
    services: list,
    restricted_ports: list[dict],
) -> dict:
    """
    Identify services containing any restricted port/protocol combination.
    Returns dict: service_href -> service_name.

    restricted_ports format: [{"port": 22, "proto": 6}, ...]
    """
    port_numbers = [rp["port"] for rp in restricted_ports]
    logging.info(f"Scanning services for restricted ports: {port_numbers}")
    restricted = {}

    for svc in services:
        for port_info in svc.get("service_ports", []):
            port = port_info.get("port")
            to_port = port_info.get("to_port")

            if port and to_port:
                if any(port <= rp <= to_port for rp in port_numbers):
                    restricted[svc.get("href", "")] = svc.get("name", "Unknown")
                    break
            elif port and port in port_numbers:
                restricted[svc.get("href", "")] = svc.get("name", "Unknown")
                break

    logging.info(f"Found {len(restricted)} services with restricted ports")
    return restricted


# =============================================================================
# HREF RESOLUTION
# =============================================================================

def build_href_lookup(labels: list, ip_lists: list, label_groups: list = None) -> dict:
    """Build href -> metadata lookup for labels, IP lists, and label groups."""
    lookup = {}

    for label in labels:
        href = label.get("href", "")
        lookup[href] = {
            "name": label.get("value", label.get("name", "Unknown")),
            "key": label.get("key", ""),
            "type": "label",
        }

    for ipl in ip_lists:
        href = ipl.get("href", "")
        lookup[href] = {
            "name": ipl.get("name", "Unknown"),
            "key": "ip_list",
            "type": "ip_list",
        }

    for lg in (label_groups or []):
        href = lg.get("href", "")
        lookup[href] = {
            "name": lg.get("name", "Unknown"),
            "key": lg.get("key", ""),
            "type": "label_group",
        }

    logging.info(f"Built href lookup: {len(lookup)} entries")
    return lookup


def resolve_actors(actors: list, href_lookup: dict) -> list[dict]:
    """Resolve rule actors (providers/consumers) to readable form."""
    resolved = []
    for actor in actors:
        if not isinstance(actor, dict):
            resolved.append({"name": str(actor), "type": "unknown", "href": "", "key": ""})
            continue

        if "actors" in actor:
            resolved.append({
                "name": actor["actors"],
                "type": "actors",
                "href": "",
                "key": "",
            })
        elif "label" in actor:
            href = actor["label"].get("href", "")
            info = href_lookup.get(href, {"name": href, "key": "unknown", "type": "label"})
            resolved.append({
                "name": info["name"],
                "type": "label",
                "key": info.get("key", ""),
                "href": href,
            })
        elif "label_group" in actor:
            href = actor["label_group"].get("href", "")
            info = href_lookup.get(href, {"name": href, "key": "unknown", "type": "label_group"})
            resolved.append({
                "name": info["name"],
                "type": "label_group",
                "key": info.get("key", ""),
                "href": href,
            })
        elif "ip_list" in actor:
            href = actor["ip_list"].get("href", "")
            info = href_lookup.get(href, {"name": href, "type": "ip_list"})
            resolved.append({
                "name": info["name"],
                "type": "ip_list",
                "key": "ip_list",
                "href": href,
            })
        elif "workload" in actor:
            href = actor["workload"].get("href", "")
            resolved.append({
                "name": href,
                "type": "workload",
                "key": "",
                "href": href,
            })
        else:
            resolved.append({"name": str(actor), "type": "unknown", "href": "", "key": ""})

    return resolved


def check_services_restricted(
    ingress_services: list,
    restricted_services: dict,
    restricted_ports: list[dict],
) -> tuple[list[str], bool]:
    """
    Resolve services and check if any are restricted.
    Returns (service_name_list, is_restricted_bool).
    """
    names = []
    is_restricted = False
    port_numbers = [rp["port"] for rp in restricted_ports]

    for svc in ingress_services:
        if not isinstance(svc, dict):
            names.append(str(svc))
            continue

        if "port" in svc:
            port = svc["port"]
            to_port = svc.get("to_port")
            proto = svc.get("proto", "")
            proto_str = {6: "TCP", 17: "UDP"}.get(proto, str(proto))

            if to_port:
                names.append(f"{proto_str}/{port}-{to_port}")
                if any(port <= rp <= to_port for rp in port_numbers):
                    is_restricted = True
            else:
                names.append(f"{proto_str}/{port}")
                if port in port_numbers:
                    is_restricted = True

        elif "href" in svc:
            href = svc["href"]
            if href in restricted_services:
                is_restricted = True
                names.append(restricted_services[href])
            else:
                names.append(href.split("/")[-1])

    return names, is_restricted


# =============================================================================
# PATTERN MATCHING
# =============================================================================

def matches_pattern(value: str, patterns: list[str]) -> bool:
    """Check if value matches any pattern (supports trailing * wildcard)."""
    for p in patterns:
        if p.endswith("*"):
            if value.startswith(p[:-1]):
                return True
        elif value == p:
            return True
    return False


# =============================================================================
# DECISION FILTER ENGINE
# =============================================================================

class DecisionEngine:
    """
    Implements the full decision filter chain from the manual control test
    guide (MON.C9.9 v1.2).

    The chain processes sources through a series of filters, mirroring the
    manual step-by-step procedure:

    1. Strip out non-end-user policy objects (permitted IPLs, labels, label groups)
    2. If no sources remain → Excluded (all permitted)
    3. If A-END_USER_COMPUTE_[EUC] present → Flag for review
    4. If any IPL- sources remain → Flag for review
    5. If remaining is app-to-app (A- src AND A- dst) → Excluded (permitted)
    6. If only env labels / label groups remain → Edge case review
    7. Everything else → Non-compliant
    """

    def __init__(self, config: dict):
        compliance = config.get("compliance", {})
        self.excluded_sources = compliance.get("excluded_sources", [])
        self.excluded_labels = compliance.get("excluded_labels", [])
        self.excluded_label_groups = compliance.get("excluded_label_groups", [])
        self.euc_patterns = compliance.get("euc_patterns", ["A-END_USER_COMPUTE_*"])

    def apply_decision_filters(
        self,
        sources: list[dict],
        destinations: list[dict],
    ) -> tuple[str, str, list[dict]]:
        """
        Apply the full decision filter chain to a rule's sources.

        Returns:
            (decision_category, decision_reason, remaining_sources)
        """
        # --- Step 1: Remove non-end-user policy objects ---
        # IMPORTANT: EUC sources (A-END_USER_COMPUTE_*) must be preserved
        # for review even though they match the general A-* exclusion pattern.
        # We check EUC patterns first to prevent them from being silently excluded.
        remaining = []
        removed = []

        for src in sources:
            name = src["name"]
            src_type = src["type"]

            # PRESERVE EUC sources — do NOT exclude these even if they match A-*
            is_euc = any(matches_pattern(name, [p]) for p in self.euc_patterns)
            if is_euc:
                remaining.append(src)
                continue

            # Excluded IP lists
            if src_type == "ip_list" and matches_pattern(name, self.excluded_sources):
                removed.append(f"{name} (permitted IPL)")
                continue

            # Excluded labels
            if src_type == "label" and matches_pattern(name, self.excluded_labels):
                removed.append(f"{name} (permitted label)")
                continue

            # Excluded label groups
            if src_type == "label_group" and matches_pattern(name, self.excluded_label_groups):
                removed.append(f"{name} (permitted label group)")
                continue

            # "All Workloads" actor
            if src_type == "actors" and name == "All Workloads":
                removed.append(f"{name} (permitted actor)")
                continue

            remaining.append(src)

        if removed:
            logging.debug(f"  Filtered out: {', '.join(removed)}")

        # --- Step 2: No remaining sources → EXCLUDED ---
        if not remaining:
            return (
                DECISION_EXCLUDE_PERMITTED_SOURCE,
                f"All sources removed as permitted: {', '.join(removed)}",
                remaining,
            )

        # --- Step 3: EUC sources → REVIEW ---
        euc_sources = [
            s for s in remaining
            if any(matches_pattern(s["name"], [p]) for p in self.euc_patterns)
        ]
        if euc_sources:
            euc_names = [s["name"] for s in euc_sources]
            return (
                DECISION_REVIEW_EUC,
                f"Contains EUC source(s): {', '.join(euc_names)}. "
                f"A-END_USER_COMPUTE contains end-user listings — "
                f"review for access outside IPL-ADMIN_VDI.",
                remaining,
            )

        # --- Step 4: Remaining IPL- sources → REVIEW ---
        ipl_sources = [
            s for s in remaining
            if s["type"] == "ip_list" or s["name"].startswith("IPL-")
        ]
        if ipl_sources:
            ipl_names = [s["name"] for s in ipl_sources]
            return (
                DECISION_REVIEW_IPL,
                f"Contains non-excluded IP List(s): {', '.join(ipl_names)}",
                remaining,
            )

        # --- Step 5: App-to-app (A- to A-) → EXCLUDED ---
        remaining_names = [s["name"] for s in remaining]
        dest_names = [d["name"] for d in destinations]

        all_src_app = (
            all(n.startswith("A-") for n in remaining_names) if remaining_names else False
        )
        all_dst_app = (
            all(n.startswith("A-") for n in dest_names) if dest_names else False
        )

        if all_src_app and all_dst_app:
            return (
                DECISION_EXCLUDE_APP_TO_APP,
                f"App-to-app: [{', '.join(remaining_names)}] "
                f"→ [{', '.join(dest_names)}]",
                remaining,
            )

        # --- Step 6: Edge cases — env/label groups only → REVIEW ---
        only_env_or_lg = all(
            s["type"] == "label_group"
            or (s["type"] == "label" and s.get("key") == "env")
            for s in remaining
        )
        if only_env_or_lg and remaining:
            edge_names = [s["name"] for s in remaining]
            return (
                DECISION_REVIEW_EDGE_CASE,
                f"Only environment labels/label groups remaining: "
                f"{', '.join(edge_names)}. "
                f"These may apply broadly to all applications.",
                remaining,
            )

        # --- Step 7: Non-compliant ---
        nc_names = [s["name"] for s in remaining]
        return (
            DECISION_NON_COMPLIANT,
            f"Non-permitted source(s) on restricted port: {', '.join(nc_names)}",
            remaining,
        )


# =============================================================================
# RULE EVALUATION
# =============================================================================

def evaluate_rule(
    rule: dict,
    ruleset_name: str,
    ruleset_scopes: str,
    href_lookup: dict,
    restricted_services: dict,
    restricted_ports: list[dict],
    decision_engine: DecisionEngine,
) -> dict:
    """Evaluate a single rule through the decision filter chain."""
    consumers = rule.get("consumers", [])
    providers = rule.get("providers", [])
    ingress_services = rule.get("ingress_services", [])

    resolved_sources = resolve_actors(consumers, href_lookup)
    resolved_destinations = resolve_actors(providers, href_lookup)
    service_names, is_restricted = check_services_restricted(
        ingress_services, restricted_services, restricted_ports
    )

    src_str = "; ".join(s["name"] for s in resolved_sources) or "N/A"
    dst_str = "; ".join(d["name"] for d in resolved_destinations) or "N/A"
    svc_str = "; ".join(service_names) or "N/A"

    entry = {
        "ruleset": ruleset_name,
        "scopes": ruleset_scopes,
        "rule_href": rule.get("href", "N/A"),
        "sources_original": src_str,
        "sources_remaining": "",
        "destinations": dst_str,
        "services": svc_str,
        "enabled": rule.get("enabled", True),
        "decision": "",
        "decision_reason": "",
    }

    # Skip if no restricted ports
    if not is_restricted:
        entry["decision"] = "N/A – No Restricted Ports"
        entry["decision_reason"] = "Rule does not contain restricted ports/services"
        return entry

    # Skip disabled rules
    if not rule.get("enabled", True):
        entry["decision"] = "N/A – Rule Disabled"
        entry["decision_reason"] = "Disabled rules do not permit traffic"
        return entry

    # Run through decision filter chain
    decision, reason, remaining = decision_engine.apply_decision_filters(
        resolved_sources, resolved_destinations
    )

    entry["decision"] = decision
    entry["decision_reason"] = reason
    entry["sources_remaining"] = (
        "; ".join(s["name"] for s in remaining) if remaining else "(none)"
    )

    return entry


# =============================================================================
# SCOPE HELPERS
# =============================================================================

def extract_scope_string(ruleset: dict, href_lookup: dict) -> str:
    scope_parts = []
    for scope_set in ruleset.get("scopes", []):
        if isinstance(scope_set, list):
            for entry in scope_set:
                if isinstance(entry, dict):
                    href = entry.get("label", {}).get("href", "")
                    info = href_lookup.get(href, {"name": href, "key": "?"})
                    scope_parts.append(f"{info.get('key', '')}:{info['name']}")
    return " | ".join(scope_parts) or "Unscoped"


def is_production_scope(
    ruleset: dict, href_lookup: dict, prod_values: list[str]
) -> bool:
    prod_lower = [v.lower() for v in prod_values]
    for scope_set in ruleset.get("scopes", []):
        if isinstance(scope_set, list):
            for entry in scope_set:
                if isinstance(entry, dict):
                    href = entry.get("label", {}).get("href", "")
                    info = href_lookup.get(href, {})
                    if (info.get("key") == "env"
                            and info.get("name", "").lower() in prod_lower):
                        return True
    return False


def is_extra_scope_rule(rule: dict) -> bool:
    return rule.get("unscoped_consumers", False)


# =============================================================================
# API MODE
# =============================================================================

def process_rulesets_api(
    client: IllumioAPIClient, config: dict
) -> tuple[list, list, list, dict]:
    """
    Pull and process rulesets from PCE API.
    Returns: (non_compliant, needs_review, excluded, stats)
    """
    compliance = config.get("compliance", {})
    restricted_ports = compliance.get("restricted_ports", [
        {"port": 22, "proto": 6},
        {"port": 23, "proto": 6},
        {"port": 3389, "proto": 6},
        {"port": 3389, "proto": 17},
        {"port": 7389, "proto": 6},
    ])
    prod_values = compliance.get("production_env_values", [
        "Production", "Prod", "E-Production", "E-Prod",
    ])

    # Fetch all data from PCE
    services = client.get_services()
    labels = client.get_labels()
    ip_lists = client.get_ip_lists()
    label_groups = client.get_label_groups()
    rulesets = client.get_rulesets()

    # Build lookups
    href_lookup = build_href_lookup(labels, ip_lists, label_groups)
    restricted_svc = identify_restricted_services(services, restricted_ports)
    engine = DecisionEngine(config)

    non_compliant, needs_review, excluded = [], [], []
    stats = {
        "total_rulesets": len(rulesets),
        "production_rulesets": 0,
        "total_rules_scanned": 0,
        "extra_scope_rules": 0,
        "rules_with_restricted_ports": 0,
        "non_compliant": 0,
        "needs_review": 0,
        "excluded": 0,
        "skipped_non_production": 0,
        "skipped_intra_scope": 0,
        "skipped_disabled": 0,
        "skipped_no_restricted_ports": 0,
    }

    for ruleset in rulesets:
        rs_name = ruleset.get("name", "Unknown")

        if not is_production_scope(ruleset, href_lookup, prod_values):
            stats["skipped_non_production"] += 1
            continue

        stats["production_rulesets"] += 1
        scope_str = extract_scope_string(ruleset, href_lookup)
        rules = ruleset.get("rules", [])
        logging.info(f"Processing: {rs_name} ({len(rules)} rules)")

        for rule in rules:
            stats["total_rules_scanned"] += 1

            if not is_extra_scope_rule(rule):
                stats["skipped_intra_scope"] += 1
                continue

            stats["extra_scope_rules"] += 1

            result = evaluate_rule(
                rule, rs_name, scope_str, href_lookup,
                restricted_svc, restricted_ports, engine,
            )

            decision = result["decision"]

            if decision.startswith("N/A"):
                if "Disabled" in decision:
                    stats["skipped_disabled"] += 1
                else:
                    stats["skipped_no_restricted_ports"] += 1
                excluded.append(result)
                stats["excluded"] += 1
            elif decision.startswith("Exclude"):
                stats["rules_with_restricted_ports"] += 1
                excluded.append(result)
                stats["excluded"] += 1
            elif decision.startswith("Keep for Review"):
                stats["rules_with_restricted_ports"] += 1
                needs_review.append(result)
                stats["needs_review"] += 1
            else:
                stats["rules_with_restricted_ports"] += 1
                non_compliant.append(result)
                stats["non_compliant"] += 1

    return non_compliant, needs_review, excluded, stats


# =============================================================================
# CSV FALLBACK MODE
# =============================================================================

def process_csv_fallback(
    csv_path: str,
    config: dict,
    client: Optional[IllumioAPIClient] = None,
) -> tuple[list, list, list, dict]:
    """
    Process rules from CSV export (fallback mode).
    Uses API for service resolution if client is available.
    """
    compliance = config.get("compliance", {})
    restricted_ports = compliance.get("restricted_ports", [
        {"port": 22, "proto": 6}, {"port": 23, "proto": 6},
        {"port": 3389, "proto": 6}, {"port": 3389, "proto": 17},
        {"port": 7389, "proto": 6},
    ])

    logging.info(f"CSV Fallback: Reading {csv_path}")

    restricted_svc_names = set()
    if client:
        try:
            services = client.get_services()
            svc_map = identify_restricted_services(services, restricted_ports)
            restricted_svc_names = set(svc_map.values())
        except Exception as e:
            logging.warning(f"Could not fetch services for CSV mode: {e}")

    port_numbers = [rp["port"] for rp in restricted_ports]

    with open(csv_path, mode="r") as f:
        rows = list(csv.DictReader(f))
    logging.info(f"Read {len(rows)} rules from CSV")

    engine = DecisionEngine(config)
    non_compliant, needs_review, excluded = [], [], []
    stats = {
        "total_rulesets": "N/A (CSV)",
        "production_rulesets": "N/A (CSV)",
        "total_rules_scanned": len(rows),
        "extra_scope_rules": len(rows),
        "rules_with_restricted_ports": 0,
        "non_compliant": 0,
        "needs_review": 0,
        "excluded": 0,
        "skipped_non_production": 0,
        "skipped_intra_scope": 0,
        "skipped_disabled": 0,
        "skipped_no_restricted_ports": 0,
    }

    for row in rows:
        ruleset_name = row.get("ruleset_name", "")
        if not ruleset_name:
            continue

        # Parse sources into structured format
        src_labels = [s.strip() for s in row.get("src_labels", "").split(";") if s.strip()]
        src_iplists = [s.strip() for s in row.get("src_iplists", "").split(";") if s.strip()]

        sources = []
        for s in src_labels:
            key = "app" if s.startswith("A-") else "env" if s.startswith("E-") else "role" if s.startswith("R-") else "unknown"
            sources.append({"name": s, "type": "label", "key": key, "href": ""})
        for s in src_iplists:
            sources.append({"name": s, "type": "ip_list", "key": "ip_list", "href": ""})

        # Parse destinations
        dst_labels = [d.strip() for d in row.get("dst_labels", "").split(";") if d.strip()]
        dst_iplists = [d.strip() for d in row.get("dst_iplists", "").split(";") if d.strip()]

        destinations = []
        for d in dst_labels:
            destinations.append({"name": d, "type": "label", "key": "", "href": ""})
        for d in dst_iplists:
            destinations.append({"name": d, "type": "ip_list", "key": "", "href": ""})

        # Check services for restricted ports
        svc_list = [s.strip() for s in row.get("services", "").split(";") if s.strip()]
        contains_restricted = any(s in restricted_svc_names for s in svc_list)
        if not contains_restricted:
            for svc_name in svc_list:
                for rp in port_numbers:
                    if str(rp) in svc_name:
                        contains_restricted = True
                        break
                if contains_restricted:
                    break

        scope_str = row.get("ruleset_scope", "").replace("app:", "").replace("env:", "")
        src_str = "; ".join(s["name"] for s in sources)
        dst_str = "; ".join(d["name"] for d in destinations)

        entry = {
            "ruleset": ruleset_name,
            "scopes": scope_str,
            "rule_href": "N/A (CSV)",
            "sources_original": src_str,
            "sources_remaining": "",
            "destinations": dst_str,
            "services": "; ".join(svc_list),
            "enabled": True,
            "decision": "",
            "decision_reason": "",
        }

        if not contains_restricted:
            entry["decision"] = "N/A – No Restricted Ports"
            entry["decision_reason"] = "No restricted ports/services"
            excluded.append(entry)
            stats["excluded"] += 1
            stats["skipped_no_restricted_ports"] += 1
            continue

        stats["rules_with_restricted_ports"] += 1

        decision, reason, remaining = engine.apply_decision_filters(sources, destinations)
        entry["decision"] = decision
        entry["decision_reason"] = reason
        entry["sources_remaining"] = (
            "; ".join(s["name"] for s in remaining) if remaining else "(none)"
        )

        if decision.startswith("Exclude"):
            excluded.append(entry)
            stats["excluded"] += 1
        elif decision.startswith("Keep for Review"):
            needs_review.append(entry)
            stats["needs_review"] += 1
        else:
            non_compliant.append(entry)
            stats["non_compliant"] += 1

    return non_compliant, needs_review, excluded, stats


# =============================================================================
# EXCEL REPORT
# =============================================================================

HDR_FONT = Font(bold=True, color="FFFFFF", size=11)
FILL_BLUE = PatternFill(start_color="2F5496", end_color="2F5496", fill_type="solid")
FILL_RED = PatternFill(start_color="C00000", end_color="C00000", fill_type="solid")
FILL_AMBER = PatternFill(start_color="BF8F00", end_color="BF8F00", fill_type="solid")
FILL_GREEN = PatternFill(start_color="548235", end_color="548235", fill_type="solid")
FILL_GRAY = PatternFill(start_color="404040", end_color="404040", fill_type="solid")
PASS_BG = PatternFill(start_color="E2EFDA", end_color="E2EFDA", fill_type="solid")
FAIL_BG = PatternFill(start_color="FCE4EC", end_color="FCE4EC", fill_type="solid")
REVIEW_BG = PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid")
THIN = Border(
    left=Side(style="thin"), right=Side(style="thin"),
    top=Side(style="thin"), bottom=Side(style="thin"),
)

RULE_HEADERS = [
    "Ruleset", "Scopes", "Rule HREF", "Sources (Original)",
    "Sources (After Filter)", "Destinations", "Services",
    "Decision Filter", "Decision Reason",
]


def style_header(ws, row: int, fill: PatternFill):
    for cell in ws[row]:
        cell.font = HDR_FONT
        cell.fill = fill
        cell.alignment = Alignment(horizontal="center", wrap_text=True)
        cell.border = THIN


def auto_width(ws, max_w=55):
    for col_idx, col in enumerate(ws.columns, 1):
        mx = max((len(str(c.value or "")) for c in col), default=8)
        ws.column_dimensions[get_column_letter(col_idx)].width = min(mx + 2, max_w)


def write_rules_sheet(ws, rules: list[dict], fill: PatternFill, empty_msg: str):
    ws.append(RULE_HEADERS)
    style_header(ws, 1, fill)

    if not rules:
        ws.append([empty_msg] + [""] * (len(RULE_HEADERS) - 1))
        ws.cell(row=2, column=1).font = Font(italic=True, color="808080")
    else:
        for r in rules:
            ws.append([
                r.get("ruleset", ""),
                r.get("scopes", ""),
                r.get("rule_href", ""),
                r.get("sources_original", ""),
                r.get("sources_remaining", ""),
                r.get("destinations", ""),
                r.get("services", ""),
                r.get("decision", ""),
                r.get("decision_reason", ""),
            ])
    auto_width(ws)


def format_port_display(ports_config: list) -> str:
    """Format restricted ports for display in report."""
    parts = []
    for rp in ports_config:
        if isinstance(rp, dict):
            proto = {6: "TCP", 17: "UDP"}.get(rp.get("proto", 6), str(rp.get("proto", "?")))
            parts.append(f"{rp['port']}/{proto}")
        else:
            parts.append(str(rp))
    return ", ".join(parts)


def generate_report(
    non_compliant: list,
    needs_review: list,
    excluded: list,
    stats: dict,
    log_records: list,
    config: dict,
    output_path: str,
    mode: str,
) -> str:
    """Generate the Excel compliance report with all sheets."""
    wb = Workbook()
    pce = config["_pce"]
    compliance = config.get("compliance", {})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    user = getpass.getuser()
    host = platform.node()

    # ---- Sheet 1: Audit Summary ----
    ws = wb.active
    ws.title = "Audit Summary"

    summary_rows = [
        (f"{CONTROL_ID} — {CONTROL_NAME} — Control Test Report", ""),
        ("", ""),
        ("EXECUTION METADATA", ""),
        ("Script Version", __version__),
        ("Control ID", CONTROL_ID),
        ("Control Name", CONTROL_NAME),
        ("Execution Timestamp", now),
        ("Executed By", user),
        ("Hostname", host),
        ("PCE Target", pce["fqdn"]),
        ("Organization ID", pce["org_id"]),
        ("Data Source", f"{'Illumio API (Direct)' if mode == 'api' else 'CSV Fallback'}: {mode}"),
        ("", ""),
        ("SCAN SCOPE", ""),
        ("Environment Filter", "Production"),
        ("Rule Scope Filter", "Extra-Scope Only"),
        ("Rule Status Filter", "Enabled Only"),
        ("Restricted Ports", format_port_display(
            compliance.get("restricted_ports", [])
        )),
        ("", ""),
        ("SCAN STATISTICS", ""),
        ("Total Rulesets Fetched", stats.get("total_rulesets", "N/A")),
        ("Production Rulesets Evaluated", stats.get("production_rulesets", "N/A")),
        ("Skipped (Non-Production)", stats.get("skipped_non_production", 0)),
        ("Total Rules Scanned", stats.get("total_rules_scanned", 0)),
        ("Extra-Scope Rules Evaluated", stats.get("extra_scope_rules", 0)),
        ("Skipped (Intra-Scope)", stats.get("skipped_intra_scope", 0)),
        ("Skipped (Disabled)", stats.get("skipped_disabled", 0)),
        ("Skipped (No Restricted Ports)", stats.get("skipped_no_restricted_ports", 0)),
        ("Rules with Restricted Ports", stats.get("rules_with_restricted_ports", 0)),
        ("", ""),
        ("DECISION FILTER RESULTS", ""),
        ("❌ Non-Compliant", stats.get("non_compliant", 0)),
        ("⚠️  Requires Manual Review", stats.get("needs_review", 0)),
        ("✅ Excluded / Compliant", stats.get("excluded", 0)),
        ("", ""),
    ]

    nc = stats.get("non_compliant", 0)
    rv = stats.get("needs_review", 0)
    if nc == 0 and rv == 0:
        result_text = "PASS — No non-compliant or review-pending rules found"
    elif nc == 0 and rv > 0:
        result_text = f"CONDITIONAL — {rv} rule(s) require manual review"
    else:
        result_text = f"FAIL — {nc} non-compliant rule(s) found, {rv} require review"

    summary_rows.append(("CONTROL TEST RESULT", result_text))
    summary_rows.append(("", ""))
    summary_rows.append(("DECISION FILTER CHAIN (Applied in Order)", ""))
    summary_rows.append(("Step 1", "Remove non-end-user policy objects (permitted IPLs, labels, label groups)"))
    summary_rows.append(("Step 2", "If no sources remain → Excluded (all sources permitted)"))
    summary_rows.append(("Step 3", "If A-END_USER_COMPUTE_[EUC] present → Flag for manual review"))
    summary_rows.append(("Step 4", "If remaining IPL- sources → Flag for manual review"))
    summary_rows.append(("Step 5", "If app-to-app (A- src AND A- dst) → Excluded (permitted)"))
    summary_rows.append(("Step 6", "If only env labels/label groups remain → Edge case review"))
    summary_rows.append(("Step 7", "Everything remaining → Non-Compliant"))
    summary_rows.append(("", ""))
    summary_rows.append(("EXCLUDED SOURCES (from config.yaml)", ""))

    for src in compliance.get("excluded_sources", []):
        summary_rows.append((f"  IPL: {src}", ""))
    for lbl in compliance.get("excluded_labels", []):
        summary_rows.append((f"  Label: {lbl}", ""))
    for lg in compliance.get("excluded_label_groups", []):
        summary_rows.append((f"  Label Group: {lg}", ""))
    for euc in compliance.get("euc_patterns", []):
        summary_rows.append((f"  EUC Pattern (Review): {euc}", ""))

    for row_data in summary_rows:
        ws.append(row_data)

    # Style
    ws["A1"].font = Font(bold=True, size=14)
    section_labels = ["EXECUTION METADATA", "SCAN SCOPE", "SCAN STATISTICS",
                      "DECISION FILTER RESULTS", "CONTROL TEST RESULT",
                      "DECISION FILTER CHAIN", "EXCLUDED SOURCES"]
    for row_cells in ws.iter_rows(min_row=1, max_row=ws.max_row, max_col=1):
        for cell in row_cells:
            val = str(cell.value or "")
            if any(s in val for s in section_labels):
                cell.font = Font(bold=True, size=12, color="2F5496")
            if "CONTROL TEST RESULT" in val:
                res_cell = ws.cell(row=cell.row, column=2)
                if "PASS" in str(res_cell.value or ""):
                    res_cell.fill = PASS_BG
                    res_cell.font = Font(bold=True, color="548235", size=12)
                elif "CONDITIONAL" in str(res_cell.value or ""):
                    res_cell.fill = REVIEW_BG
                    res_cell.font = Font(bold=True, color="BF8F00", size=12)
                elif "FAIL" in str(res_cell.value or ""):
                    res_cell.fill = FAIL_BG
                    res_cell.font = Font(bold=True, color="C00000", size=12)

    ws.column_dimensions["A"].width = 45
    ws.column_dimensions["B"].width = 70

    # ---- Sheet 2: Non-Compliant ----
    ws_nc = wb.create_sheet("Non-Compliant")
    write_rules_sheet(ws_nc, non_compliant, FILL_RED,
                      "No non-compliant rules found — PASS")

    # ---- Sheet 3: Requires Review ----
    ws_rv = wb.create_sheet("Requires Review")
    write_rules_sheet(ws_rv, needs_review, FILL_AMBER,
                      "No rules require manual review")

    # ---- Sheet 4: Excluded / Compliant ----
    ws_ex = wb.create_sheet("Excluded - Compliant")
    write_rules_sheet(ws_ex, excluded, FILL_GREEN,
                      "No excluded/compliant rules")

    # ---- Sheet 5: Execution Log ----
    ws_log = wb.create_sheet("Execution Log")
    ws_log.append(["Timestamp", "Level", "Message"])
    style_header(ws_log, 1, FILL_GRAY)
    for rec in log_records:
        ws_log.append([rec["timestamp"], rec["level"], rec["message"]])
    auto_width(ws_log)

    # Save and hash
    wb.save(output_path)
    logging.info(f"Report saved: {output_path}")

    with open(output_path, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    logging.info(f"SHA-256: {sha}")

    return sha


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description=f"{CONTROL_ID} — Admin VDI Control Test (Automated)",
    )
    parser.add_argument("--config", "-c", default=DEFAULT_CONFIG_PATH,
                        help=f"Config YAML path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--csv", default=None,
                        help="CSV file for fallback mode")
    parser.add_argument("--output", "-o", default=None,
                        help="Output Excel file path")
    parser.add_argument("--version", "-v", action="version",
                        version=f"%(prog)s {__version__}")
    return parser.parse_args()


def main():
    args = parse_args()
    log_capture = setup_logging()

    logging.info("=" * 72)
    logging.info(f"{CONTROL_ID} — Admin VDI Control Test v{__version__}")
    logging.info("=" * 72)

    try:
        config = load_config(args.config)
        pce = config["_pce"]
        compliance = config.get("compliance", {})

        logging.info(f"PCE: {pce['fqdn']} | Org: {pce['org_id']}")
        logging.info(f"Restricted Ports: {format_port_display(compliance.get('restricted_ports', []))}")

        excl_count = (len(compliance.get("excluded_sources", []))
                      + len(compliance.get("excluded_labels", []))
                      + len(compliance.get("excluded_label_groups", [])))
        logging.info(f"Excluded source patterns: {excl_count}")

        client = IllumioAPIClient(
            pce["fqdn"], pce["port"], pce["org_id"],
            pce["api_user"], pce["api_key"],
        )

        if args.csv:
            mode = f"csv:{args.csv}"
            logging.info(f"Mode: CSV fallback ({args.csv})")
            nc, rv, ex, stats = process_csv_fallback(args.csv, config, client)
        else:
            mode = "api"
            logging.info("Mode: Direct API pull from PCE")
            nc, rv, ex, stats = process_rulesets_api(client, config)

        # Print results
        logging.info("=" * 72)
        logging.info("RESULTS")
        logging.info(f"  Total Rules Scanned:       {stats.get('total_rules_scanned', 0)}")
        logging.info(f"  Extra-Scope Evaluated:     {stats.get('extra_scope_rules', 0)}")
        logging.info(f"  With Restricted Ports:     {stats.get('rules_with_restricted_ports', 0)}")
        logging.info(f"  ❌ Non-Compliant:          {stats.get('non_compliant', 0)}")
        logging.info(f"  ⚠️  Requires Review:       {stats.get('needs_review', 0)}")
        logging.info(f"  ✅ Excluded / Compliant:   {stats.get('excluded', 0)}")
        logging.info("=" * 72)

        nc_count = stats.get("non_compliant", 0)
        rv_count = stats.get("needs_review", 0)

        if nc_count == 0 and rv_count == 0:
            logging.info("CONTROL TEST RESULT: PASS")
        elif nc_count == 0:
            logging.warning(f"CONTROL TEST RESULT: CONDITIONAL — {rv_count} rule(s) need review")
        else:
            logging.error(f"CONTROL TEST RESULT: FAIL — {nc_count} non-compliant, {rv_count} need review")

        # Generate report
        if args.output:
            out = args.output
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out = f"VDI_Control_Test_{CONTROL_ID}_{ts}.xlsx"

        sha = generate_report(nc, rv, ex, stats, log_capture.records, config, out, mode)

        logging.info(f"Report: {out}")
        logging.info(f"SHA-256: {sha}")
        logging.info("Execution complete.")

        # Exit codes: 0=pass, 1=fail, 2=error, 3=conditional
        if nc_count > 0:
            return 1
        elif rv_count > 0:
            return 3
        return 0

    except Exception as e:
        logging.critical(f"FATAL: {e}", exc_info=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
