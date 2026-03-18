# MON.C9.9 — Admin VDI Control Test (Automated)

**Version:** 3.0.0  
**Control:** MON.C9.9 — Admin VDI Restrictions  
**Guide:** Admin VDI Control Test Execution v1.2  
**Team:** Cybersecurity Tech Ops — Illuminati Team

## Purpose

This script automates the MON.C9.9 Admin VDI Restrictions control test. It replaces the manual procedure documented in the Admin VDI Control Test Guide v1.2, producing audit-ready evidence in a structured Excel report.

The control tests whether non-approved connections to production servers exist using administrative protocols (SSH, Telnet, RDP). The script scans Illumio PCE extra-scope rulesets in the E-PD (Production) environment for rules that allow traffic over admin VDI ports from non-permitted sources.

## Prerequisites

- Python 3.10+
- Illumio PCE API credentials (API user + key)
- Network access to the PCE (`us-scp14.illum.io:443`)

### Python Dependencies

```bash
pip install requests pyyaml openpyxl
```

## Files

| File | Purpose |
|------|---------|
| `vdi_control_test.py` | Main script |
| `config.yaml` | Configuration — PCE connection, excluded sources, restricted ports |
| `README.md` | This file |
| `DECISION_CHAIN.md` | Detailed decision filter documentation for auditors |
| `CHANGELOG.md` | Version history |

## Configuration

### PCE Credentials

Set via environment variables (recommended) or `config.yaml`:

```bash
export ILLUMIO_API_USER="api_xxxxxxxxx"
export ILLUMIO_API_KEY="your_api_key_here"
```

Environment variables override `config.yaml` values. Never commit credentials to version control.

### Restricted Ports

Defined in `config.yaml` under `compliance.restricted_ports`:

| Port | Service | Protocol |
|------|---------|----------|
| 22 | SSH | TCP |
| 23 | Telnet | TCP |
| 3389 | RDP | TCP/UDP |
| 7389 | Secure RDP (DMZ) | TCP/UDP |

### Excluded Sources

All excluded/permitted sources are in `config.yaml`. Update the YAML when the exception list changes — no code modifications needed. Each exclusion includes the rationale from the control test guide.

## Usage

### Standard Run (API mode)

```bash
python vdi_control_test.py
```

### With Target CIs (scope to specific applications)

```bash
python vdi_control_test.py --target-cis "236847,236468,236719"
```

### Custom Output Path

```bash
python vdi_control_test.py -o "/path/to/MON C9/Admin VDI/report.xlsx"
```

### EDR Export (Splunk ingest for Seth Jones / Mike Morfin)

```bash
python vdi_control_test.py --edr-export "/shared/folder/illumio_ruleset.csv"
```

### Custom Config

```bash
python vdi_control_test.py -c /path/to/config.yaml
```

### All Options Combined

```bash
python vdi_control_test.py \
  --target-cis "236847,236468" \
  --edr-export "/shared/illumio_ruleset.csv" \
  -o "VDI_Test_Q1_2026.xlsx"
```

## Output

### Excel Report (5 sheets)

| Sheet | Description |
|-------|-------------|
| **Audit Summary** | Execution metadata, scan scope, statistics, PASS/FAIL/CONDITIONAL result, decision chain documentation, excluded source list with rationale |
| **Non-Compliant** | Rules with non-excluded IPLs or non-permitted sources on restricted ports. **These require SIR creation.** |
| **Requires Review** | Rules with A-END_USER_COMPUTE_(EUC) sources or edge cases needing manual review |
| **Excluded - Compliant** | Rules where all sources were permitted (Admin VDI, app-to-app, appliances) |
| **Execution Log** | Full timestamped log of every API call, filter decision, and processing step |

### Report Columns

| Column | Description |
|--------|-------------|
| Ruleset | Illumio ruleset name (policy) |
| Scopes | Application and environment labels (no prefixes) |
| Rule HREF | API reference for the specific rule |
| Sources (Original) | All resolved source names before filtering |
| Sources (After Filter) | Remaining sources after excluding permitted objects |
| Source Label Groups | Label groups associated with source labels |
| Destinations | Resolved destination names |
| Dest Label Groups | Label groups associated with destination labels |
| Destination Services | Restricted services matched (SVC-SSH, SVC-MS-RDP, etc.) |
| Decision Filter | The decision category applied |
| Decision Reason | Detailed explanation of why the decision was made |

### Additional Outputs

| File | Description |
|------|-------------|
| `illumio_blank_rules.json` | Rules with blank sources or destinations (for audit review) |
| `illumio_admin_vdi_log_DD-MM-YYYY.txt` | Persistent log file |
| EDR CSV (if `--edr-export`) | Flat CSV for Splunk input lookup |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | **PASS** — no non-compliant or review-pending rules |
| `1` | **FAIL** — non-compliant rules detected (SIRs needed) |
| `2` | **ERROR** — script failed during execution |
| `3` | **CONDITIONAL** — no non-compliant, but rules require manual review |

## Decision Filter Chain

The script applies the following filters in order, matching the manual procedure from the Admin VDI Control Test Guide v1.2:

| Step | Action | Result |
|------|--------|--------|
| 1 | Strip permitted sources: excluded IPLs, A-* labels, E-* labels, All Workloads, specific labels/label groups. **Preserves A-END_USER_COMPUTE_* for review.** | Sources filtered |
| 2 | No sources remain after filtering | **Excluded** — all sources were permitted policy objects |
| 3 | A-END_USER_COMPUTE_(EUC) is present | **Requires Review** — contains end-user laptops |
| 4 | Non-excluded IPL- sources remain | **Non-Compliant** — finding, SIR required |
| 5 | All remaining sources are A-*/E-* labels | **Excluded** — app-to-app traffic is permitted |
| 6 | Only label groups remain | **Requires Review** — edge case, may apply broadly |
| 7 | Everything else (R-* role labels, other) | **Non-Compliant** — finding, SIR required |

## SIR Creation Process

For each rule on the **Non-Compliant** sheet:

1. Use the SIR template "Illumio Non-Compliant Admin Rule" in ServiceNow
2. Create one SIR per application (identified by the Scopes column)
3. Include the rule details from the report
4. Note who was notified and when in a "Control Test Notes" column

## Delivering Audit Evidence

Save the following to the MON.C9.9 control directory (e.g., `3.17.2026 MON.C9.9`):

1. The generated Excel report (`.xlsx`)
2. Each sent SIR notification
3. The execution log file (`.txt`)
4. The blank rules JSON (if generated)
5. This README for context

## Audit Integrity

Each report includes:

- **Script version** embedded in the Audit Summary sheet
- **SHA-256 hash** of the output file (logged to console and log file)
- **Execution timestamp** in UTC
- **Hostname and username** of the executor
- **Full decision chain** documented in the summary for auditor reference
- **Complete execution log** embedded as a sheet in the report

## API Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `/labels?max_results=100000` | All labels (A-, R-, E-, L-) |
| `/sec_policy/draft/label_groups?max_results=100000` | Label groups (draft includes active references) |
| `/sec_policy/draft/ip_lists?max_results=100000` | IP lists (draft includes active references) |
| `/sec_policy/active/services?max_results=100000` | Active services (port definitions) |
| `/sec_policy/active/rule_sets?max_results=100000` | Active rulesets with embedded rules |

All endpoints use `max_results=100000` to fetch complete datasets in a single request.
