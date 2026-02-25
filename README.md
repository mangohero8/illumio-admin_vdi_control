# MON.C9.9 — Admin VDI Control Test (Automated)

Automated compliance scanner for non-compliant admin VDI rules in Illumio PCE.
Replaces the manual control test procedure documented in the Illumio Admin VDI
Control Test Guide v1.2.

## Overview

This tool scans Production extra-scope rulesets in Illumio for rules that allow
traffic over admin VDI ports from non-permitted sources. It applies the same
decision filter chain used in the manual procedure, producing a structured
Excel report suitable for audit evidence.

### Decision Filter Chain

The script processes each rule's sources through these steps (in order):

| Step | Action | Result |
|------|--------|--------|
| 1 | Remove non-end-user policy objects (permitted IPLs, labels, label groups) | Sources stripped |
| 2 | If no sources remain after filtering | **Excluded** — all sources permitted |
| 3 | If `A-END_USER_COMPUTE_[EUC]` is present | **Requires Review** — end-user access |
| 4 | If any `IPL-` sources remain | **Requires Review** — non-excluded IP list |
| 5 | If remaining is app-to-app (A- src AND A- dst) | **Excluded** — app-to-app permitted |
| 6 | If only env labels/label groups remain | **Requires Review** — edge case |
| 7 | Everything else | **Non-Compliant** |

### Restricted Ports

| Port | Protocol | Service |
|------|----------|---------|
| 22 | TCP | SSH |
| 23 | TCP | Telnet |
| 3389 | TCP | RDP |
| 3389 | UDP | RDP |
| 7389 | TCP | Secure RDP (custom) |

## Setup

### Requirements

```bash
pip install requests pyyaml openpyxl
```

### Configuration

Edit `config.yaml` with your PCE connection details.

**Credentials** (choose one or both — env vars take precedence):

```bash
export ILLUMIO_API_USER="api_xxxxxxxxx"
export ILLUMIO_API_KEY="your_api_key"
export ILLUMIO_FQDN="us-scp14.illum.io"
export ILLUMIO_PORT="8443"
export ILLUMIO_ORG_ID="1"
```

### Updating Excluded Sources

All excluded/permitted sources are in `config.yaml` under the `compliance` section.
No code changes needed when the exception list changes — just update the YAML.

## Usage

### API Mode (primary)

```bash
python vdi_control_test.py
```

### CSV Fallback Mode

```bash
python vdi_control_test.py --csv rule_export.csv
```

### Custom output / config

```bash
python vdi_control_test.py -o /shared/MON_C9/report.xlsx -c /path/to/config.yaml
```

## Output

### Excel Report (5 sheets)

| Sheet | Contents |
|-------|----------|
| **Audit Summary** | Execution metadata, scan scope, statistics, pass/fail/conditional result, decision chain documentation, excluded source list |
| **Non-Compliant** | Rules that failed all filters — action required |
| **Requires Review** | Rules needing manual review (EUC, non-excluded IPLs, edge cases) |
| **Excluded - Compliant** | Rules that passed filters (permitted sources, app-to-app, no restricted ports) |
| **Execution Log** | Full timestamped log of the scan |

### Report Columns

Each rule sheet includes: Ruleset, Scopes, Rule HREF, Sources (Original),
Sources (After Filter), Destinations, Services, Decision Filter, Decision Reason.

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | **PASS** — no non-compliant or review-pending rules |
| `1` | **FAIL** — non-compliant rules detected |
| `2` | **ERROR** — script failed during execution |
| `3` | **CONDITIONAL** — no non-compliant rules, but some require manual review |

### Audit Artifacts

Each report includes:
- Execution timestamp, user, hostname
- PCE target and org ID
- Script version (`__version__`)
- SHA-256 hash of the output file (logged and printed)
- Full decision chain documentation embedded in summary sheet

## Version History

| Version | Changes |
|---------|---------|
| 2.0.0 | Full decision filter chain, 3-bucket output (NC/Review/Excluded), EUC handling, UDP/3389, label group support, configurable excluded sources |
| 1.0.0 | Initial automated version |

---
*Cybersecurity Tech Ops — Illuminati Team*
