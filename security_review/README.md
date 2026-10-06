# Bell Cyber STIRT Secure Code Review

This directory holds the deliverables of an authorized, CTF-style secure code review of the
Splunk `security_content` (ESCU) repository, performed by the Bell Cyber Security Threat
Intelligence and Response Team.

- **Commit reviewed:** `develop @ 4cd62e8` (2026-09-08)
- **Assessment date:** 2026-10-06
- **Unique findings:** 111 (0 Critical, 13 High, 31 Medium, 47 Low, 20 Informational)
- **Classification:** Confidential

## Documents

| File | Contents |
|---|---|
| `BellCyber_SecureCodeReview_security_content.pdf` / `.docx` | The full report: executive summary, scope and method, per-file risk ratings, all 111 detailed findings with proof of concept and fixed code, findings catalogue, software composition and licensing analysis, verification guide, SANS secure-coding assessment, refactoring recommendations, and the framework mappings. |
| `mappings/BellCyber_Mapping_CWE_Top25.*` | Findings mapped to CWE and the 2024 CWE Top 25. |
| `mappings/BellCyber_Mapping_OWASP_Top10.*` | Findings mapped to OWASP Top 10 2021. |
| `mappings/BellCyber_Mapping_MITRE_ATTACK.*` | Findings mapped to MITRE ATT&CK techniques. |
| `mappings/BellCyber_Mapping_NIST.*` | Findings mapped to NIST SP 800-53 Rev. 5 and NIST CSF 2.0. |
| `mappings/BellCyber_Mapping_ISO27001.*` | Findings mapped to ISO/IEC 27001:2022 Annex A. |
| `mappings/BellCyber_Mapping_SANS.*` | Findings mapped to the SANS Secure Coding Practices. |
| `sources/` | Markdown sources behind the generated documents, for traceability. |

## How findings are identified

Each finding has a stable identifier whose prefix names the review area:

- `PB1`, `PB2` — SOAR response playbooks
- `CF` — SOAR custom functions
- `DET` — detection content, baselines and stories
- `APP` — app template, dashboards, lookups and macros
- `CI` — CI/CD pipeline and build scripts
- `DEP` — software composition, end-of-life and licensing
- `SEC` — secrets and sensitive data

Identifiers (for example `PB2-01`) resolve to the detailed write-ups in Section 4 of the full
report. The report's Section 4 also lists which identifiers were consolidated where two
reviewers raised the same root cause.

## Important note on exploitability

The repository is detection content and response automation, not a deployable web application,
so no live site was exercised through a browser. Every string-building weakness was reproduced
in an isolated sandbox with a stubbed SOAR SDK; no external system or live credential was
touched. The verification guide (Section 7) states which disposable systems to use to reproduce
each class of finding and to confirm the fixes.
