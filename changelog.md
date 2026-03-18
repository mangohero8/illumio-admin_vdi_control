# Changelog — MON.C9.9 Admin VDI Control Test

## [3.0.0] — 2026-03-17

### Architecture
- Rebuilt on proven working export script's API fetch logic
- `max_results=100000` single-shot fetch (no pagination issues)
- Draft endpoints for IP lists and label groups (matches active rule references)
- Label map with A-/R-/E-/L- prefix filtering
- IP list draft↔active href dual-mapping
- `actors == "ams"` → "All Workloads" resolution

### Decision Filter Chain
- Complete 7-step decision chain matching Admin VDI Control Test Guide v1.2
- EUC check (A-END_USER_COMPUTE_*) runs BEFORE A-* exclusion to prevent silent removal
- Non-excluded IPLs (IPL-VPN_USERS, IPL-INTERNAL_10S, etc.) classified as Non-Compliant
- App-to-app (A-* to A-*) correctly excluded
- Edge case handling for standalone label groups

### Configuration
- External `config.yaml` for all excluded sources, restricted ports, EUC patterns
- Environment variable overrides for PCE credentials
- Each excluded source includes audit rationale from the control test guide
- No code changes needed when exception lists change

### Output
- Three-bucket Excel report: Non-Compliant, Requires Review, Excluded-Compliant
- Audit Summary sheet with execution metadata, scan statistics, PASS/FAIL result
- Decision chain documentation embedded in report
- Execution log embedded as Excel sheet
- SHA-256 hash of output for tamper evidence
- Blank rules written to JSON for audit review
- EDR CSV export for Splunk ingest (`--edr-export`)

### CLI
- `--target-cis` replaces interactive prompt
- `--output` for custom report path
- `--edr-export` for Splunk CSV
- `--config` for custom config file
- Exit codes: 0=PASS, 1=FAIL, 2=ERROR, 3=CONDITIONAL

### Fixes
- Corrected IPL names: IPL-WEB_DMZ_DC1G2 (not DC162), IPL-WEB_DMZ_LTM_PD (not 1TM)
- Added LG-E-NON_PRODUCTION_ENVIRONMENTS to excluded label groups
- E-PD strict scope match (not fuzzy "Production" matching)
- PCE port 443 (SaaS), org 3801148

## [2.1.0] — 2026-03-13

### Changes
- Added offset-based pagination (replaced by max_results=100000 in v3)
- Prefix stripping for scopes, sources, destinations

## [1.0.0] — 2025

### Initial Version
- Manual CSV export + Python filtering
- Basic compliant/non-compliant classification
- CSV output for EDR team Splunk ingest
