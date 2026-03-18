# MON.C9.9 — Decision Filter Chain Documentation

**Control:** MON.C9.9 — Admin VDI Restrictions  
**Guide Reference:** Admin VDI Control Test Execution v1.2  
**Script Version:** 3.0.0

## Overview

This document describes the automated decision filter chain used to classify Illumio extra-scope rules as Compliant, Requires Review, or Non-Compliant for the MON.C9.9 Admin VDI Restrictions control test.

The automated chain replicates the manual steps from the Admin VDI Control Test Guide v1.2, sections "Removing Non-end user policy objects" through "Identify rules out of compliance with control."

## Scope

The test evaluates rules that meet ALL of the following criteria:

- **Environment:** E-PD (Production) scope only
- **Rule Status:** Enabled only (disabled rules do not permit traffic)
- **Services:** Must contain at least one restricted port (22, 23, 3389, 7389)
- **Rule Type:** Extra-scope (rules permitting traffic from outside the ruleset scope)

Rules not meeting all criteria are skipped before the decision chain runs.

## Pre-Filter: Source Resolution

Before the decision chain, source actors are resolved from API href references to human-readable names:

- `actors: "ams"` → "All Workloads"
- IP list hrefs → IP list names (e.g., "IPL-VPN_USERS")
- Label hrefs → Label values (e.g., "A-MYAPP", "R-DATABASE")
- Label group membership is tracked for reporting but not used in filtering

## Decision Filter Chain

### Step 1: Strip Permitted Sources

Each source in the rule is evaluated. Permitted (non-end-user) sources are removed. The EUC check runs first to prevent A-END_USER_COMPUTE from being silently excluded by the A-* pattern.

**Processing order per source:**

1. If source matches EUC pattern (`A-END_USER_COMPUTE_*`) → **KEEP** (do not strip)
2. If source matches excluded label pattern → **STRIP**
   - `A-*` (application labels — app-originated traffic)
   - `E-*` (environment labels)
   - `R-METTLE-CI` (specific permitted role)
   - `METTLECI-*` (correlation labels)
3. If source matches excluded IP list → **STRIP**
   - `IPL-ADMIN_VDI` — expected traffic path
   - `IPL-CLUSTER_LINK_LOCAL` — link-local, not routable outside VLAN
   - `IPL-MAINFRAME_*` — mainframe-originated, not end-user
   - `IPL-GUARDIUM-100028` — appliance
   - `IPL-IPT_VOICE_INFRASTRUCTURE_CORE_DATA_CENTER_NETWORKS` — appliance
   - `IPL-LOAD_BALANCERS` — appliance
   - `IPL-WEB_DMZ_DC1G2` — appliance
   - `IPL-WEB_DMZ_DC2` — appliance
   - `IPL-WEB_DMZ_LTM_PD-900055` — appliance
   - `IPL-INTERNAL_LTM_PD-900055` — appliance
4. If source matches excluded label group → **STRIP**
   - `LG-E-NON_QUARANTINE`
   - `LG-E-NON_PRODUCTION_ENVIRONMENTS`
5. If source is "All Workloads" → **STRIP**

### Step 2: No Remaining Sources

If all sources were stripped in Step 1, the rule is **Excluded** — every source was a permitted non-end-user policy object.

**Decision:** `Exclude – No Remaining Sources With Access`

### Step 3: EUC Check

If any remaining source matches `A-END_USER_COMPUTE_*`, the rule is flagged for manual review. A-END_USER_COMPUTE contains end-user laptop listings that represent potential end-user access outside IPL-ADMIN_VDI.

**Decision:** `Keep for Review – Contains A-END_USER_COMPUTE_(EUC)`

### Step 4: Non-Excluded IP Lists

If any remaining source starts with `IPL-` (an IP list not in the excluded list), the rule is **Non-Compliant**. These represent non-admin network paths (e.g., VPN, internal networks) accessing production servers over administrative ports.

**Decision:** `Non-Compliant – Non-Excluded IP List on Restricted Port`

**Examples:** IPL-VPN_USERS, IPL-INTERNAL_10S, IPL-VIPS, IPL-HNB_OEAP, IPL-RFC1918

### Step 5: App-to-App Traffic

If all remaining sources are application (`A-*`) or environment (`E-*`) labels, the rule is **Excluded**. Application-to-application traffic over admin ports is permitted by the control.

**Decision:** `Exclude – Application to Application Traffic is Permitted`

### Step 6: Label Groups Only

If only label groups remain (no individual labels or IPLs), the rule is flagged for review. Label groups may apply broadly to all applications and need manual assessment.

**Decision:** `Keep for Review – Edge Case (Label Group Only)`

### Step 7: Non-Compliant (Default)

Any remaining sources that didn't match prior steps are **Non-Compliant**. This typically catches role labels (R-*) or other non-permitted objects.

**Decision:** `Non-Compliant – Unpermitted Source on Restricted Port`

## Mapping to Manual Guide Sections

| Automated Step | Manual Guide Section |
|---------------|---------------------|
| Pre-filter (E-PD, enabled, restricted ports) | "Searching for Rules" |
| Step 1 (strip permitted) | "Removing Non-end user policy objects" |
| Step 2 (blank sources) | "Filter Sources to ONLY INCLUDE blanks" |
| Step 3 (EUC) | "Identify End User (EUC) rules for review" |
| Step 4 (IPL-) | "Identify rules using Non-Admin IP lists" |
| Step 5 (A- to A-) | "Filter for Permitted Application Traffic" |
| Step 6 (edge cases) | "Check Edge Cases" |
| Step 7 (non-compliant) | "Identify rules out of compliance with control" |

## Configuration

All excluded sources, restricted ports, and EUC patterns are defined in `config.yaml`. The configuration can be updated without modifying the script, and each entry includes audit rationale.
