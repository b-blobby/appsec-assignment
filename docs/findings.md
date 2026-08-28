# Security Findings

## Scope

This report summarises the security assessment of the VulnTracker application using:

| Scan type | Tool | Raw report |
|---|---|---|
| SAST | Semgrep | `reports/sast.semgrep.json` |
| SCA | OSV-Scanner | `reports/sca.osv-scanner.json` |
| Container | Grype | `reports/container.grype.json` |
| IaC | Checkov | `reports/iac.checkov.json` |
| Manual review | Manual code review | N/A |

Findings are prioritised based on exploitability and business impact to VulnTracker, not only on scanner severity. VulnTracker stores information about known vulnerabilities, affected components and remediation details, so unauthorised access to its data could directly assist an attacker.

---

## Executive Summary

The most significant issues were identified in authentication, database access and dependency management.

The highest-risk application findings were:

- unsafe JWT validation allowing the `none` algorithm;
- SQL injection in scan search;
- broken object-level authorisation allowing access to another user's scan;
- plaintext password logging.

The dependency and container scans also identified outdated authentication, cryptography and runtime packages. The Helm deployment passed most Kubernetes security controls, with the remaining findings mainly related to deployment hardening and image immutability.

Several high-risk application findings were remediated in Task 3.

---

## Prioritised Findings

| # | Finding | Tool / Scan Type | Severity | Business Impact | Origin | Status |
|---|---|---|---|---|---|---|
| 1 | JWT validation allowed `alg=none` | Semgrep / SAST + manual validation | **Critical** | Could weaken authentication and allow forged identity claims, exposing protected scan data | Starter code | Remediated |
| 2 | SQL injection in scan search | Semgrep / SAST + manual validation | **Critical** | Could expose or modify vulnerability records outside the attacker's normal access | Starter code | Remediated |
| 3 | Vulnerable `python-jose` dependency | OSV-Scanner / SCA, confirmed by Grype | **Critical** | Directly affects the JWT authentication layer protecting application data | Starter dependencies | Open |
| 4 | Broken object-level authorisation (IDOR/BOLA) | Manual review | **High** | An authenticated user could read another user's vulnerability findings by changing a scan ID | Starter code | Remediated |
| 5 | Plaintext passwords written to logs | Semgrep / SAST + manual validation | **High** | Credentials could be exposed through log aggregation, backups or operational tooling | Starter code | Remediated |
| 6 | Vulnerable cryptography and request-parsing dependencies | OSV-Scanner / SCA | **High** | Known issues in security-sensitive and HTTP parsing libraries could affect authentication or API availability | Starter dependencies | Open |
| 7 | Critical/High vulnerabilities in container image | Grype / Container | **High** | Vulnerable OpenSSL, SQLite and other runtime packages increase production attack surface | Task 4 deployment artefact | Open |
| 8 | Hardcoded secrets in original configuration | Manual review | **High** | Source-code access could expose JWT, database or internal service credentials | Starter code | Remediated for deployment |
| 9 | Share password accepted in URL query parameter | Manual review | **Medium** | Passwords may leak through browser history, proxy/access logs or monitoring systems | Task 1 new feature | Mitigated |
| 10 | Kubernetes deployment hardening gaps | Checkov / IaC | **Medium** | Mutable image references and default namespace reduce deployment integrity and isolation | Task 4 deployment artefact | Open |
| 11 | GitHub Actions use mutable references | Semgrep / SAST | **Medium** | Increases CI/CD supply-chain risk if an upstream action or tag is compromised | Starter CI | Open |
| 12 | Notification service findings requiring validation | Semgrep / SAST | **Low / Informational** | Possible mass assignment and missing CSRF protection require context before being treated as exploitable | Starter code | Review |

---

## 1. JWT validation allowed `alg=none`

**Severity:** Critical  
**Tool:** Semgrep (SAST), manually validated  
**Origin:** Starter code  
**Status:** Remediated

The JWT decoder explicitly allowed the `none` algorithm in addition to the configured signing algorithm.

This is critical because JWT authentication protects access to VulnTracker scan data. Weakening signature validation could allow an attacker to impersonate another user and access protected API functionality.

**Remediation:** `none` was removed from the accepted algorithms and JWT validation was restricted to the algorithm configured by the server.

---

## 2. SQL injection in scan search

**Severity:** Critical  
**Tool:** Semgrep (SAST), manually validated  
**Origin:** Starter code  
**Status:** Remediated

The search functionality constructed SQL using user-controlled input.

A successful injection could bypass application-level controls and expose or manipulate vulnerability records belonging to other users. Because these records include affected components and remediation details, database compromise could directly support further attacks against tracked systems.

**Remediation:** Raw SQL construction was replaced with parameterised / ORM-based filtering and the search was restricted to the authenticated user's records.

---

## 3. Vulnerable `python-jose` dependency

**Severity:** Critical  
**Tool:** OSV-Scanner (SCA), also present in the built image according to Grype  
**Origin:** Starter dependencies  
**Status:** Open

The project uses `python-jose==3.3.0`. OSV-Scanner identified multiple advisories affecting this version, including CVE-2024-33663.

This finding is prioritised because `python-jose` is part of the authentication path rather than an unused utility dependency.

**Recommendation:** Upgrade to a patched supported version, retest authentication, rebuild the container image and rerun both SCA and container scans.

---

## 4. Broken object-level authorisation

**Severity:** High  
**Tool:** Manual review  
**Origin:** Starter code  
**Status:** Remediated

The original scan retrieval endpoint checked only the requested scan ID and did not verify ownership.

An authenticated user could therefore attempt to access another user's scan by changing the numeric identifier. This is a direct confidentiality issue because vulnerability data can reveal exploitable systems and components.

**Remediation:** Scan retrieval now requires both the requested `scan_id` and `owner_id == current_user.id`.

---

## 5. Plaintext password logging

**Severity:** High  
**Tool:** Semgrep (SAST), manually validated  
**Origin:** Starter code  
**Status:** Remediated

The login flow wrote submitted passwords to application logs.

Logs are commonly retained and forwarded to central systems, so this could create a secondary store of reusable credentials.

**Remediation:** Passwords and other reusable credentials were removed from log messages.

---

## 6. Vulnerable cryptography and request-parsing dependencies

**Severity:** High  
**Tool:** OSV-Scanner (SCA)  
**Origin:** Starter dependencies  
**Status:** Open

The dependency scan identified outdated packages including:

- `cryptography==38.0.1`
- `ecdsa==0.9.0`
- `python-multipart==0.0.6`
- older FastAPI / Starlette components

The cryptography packages are security-sensitive, while the request-parsing issues include denial-of-service conditions triggered by crafted HTTP input.

Not every advisory is necessarily reachable in VulnTracker, so these were grouped and assessed based on application context rather than copied individually from the scanner.

**Recommendation:** Upgrade to compatible patched versions and rerun the test suite, OSV-Scanner and container scan.

---

## 7. Vulnerabilities in the container image

**Severity:** High  
**Tool:** Grype (Container scan)  
**Origin:** Task 4 deployment artefact / base image  
**Status:** Open

Grype identified a large number of operating-system and Python package vulnerabilities in the built image.

Notable findings include:

- **CVE-2025-15467** affecting OpenSSL / `libssl3`;
- **CVE-2025-6965** affecting SQLite.

The raw count is not treated as a security score. Many findings are inherited from the Debian base image and some may not be reachable by the application. However, Critical and High vulnerabilities with available fixes should not remain in a production image.

**Recommendation:** Rebuild using an up-to-date patched Python 3.11 slim image, upgrade application dependencies and rerun Grype.

---

## 8. Hardcoded secrets in original configuration

**Severity:** High  
**Tool:** Manual review  
**Origin:** Starter code  
**Status:** Remediated for deployment

The original configuration stored sensitive values such as the JWT signing secret, database password and internal API key directly in source code.

Repository access should not provide production credentials. Exposure of the JWT signing key would be especially serious because it could enable token forgery.

**Remediation:** Sensitive configuration is now provided at runtime. The Helm deployment references secrets sourced through External Secrets rather than hardcoding secret values in manifests or Helm values.

---

## 9. Share password accepted in URL query parameter

**Severity:** Medium  
**Tool:** Manual review  
**Origin:** Task 1 new feature / assignment requirement  
**Status:** Mitigated

The required Task 1 interface allows a password in the query string:

```text
/share/{token}?password=...
```

Passwords in URLs can appear in browser history, reverse-proxy logs and monitoring systems.

**Mitigation:** The implementation prefers the `X-Share-Password` header, avoids logging the raw token/password, hashes share tokens at rest, applies cache/referrer protections and rate-limits failed password attempts.

For a production API not constrained by the assignment, query-string password support should be removed.

---

## 10. Kubernetes deployment hardening gaps

**Severity:** Medium  
**Tool:** Checkov (IaC)  
**Origin:** Task 4 deployment artefact  
**Status:** Open

Checkov identified several lower-risk deployment issues, including:

- image not pinned by digest;
- resources rendering into the default namespace;
- `imagePullPolicy: IfNotPresent`;
- secrets injected as environment variables rather than mounted as files.

These are defence-in-depth issues rather than direct application compromise.

The Helm deployment still implements strong baseline controls: non-root execution, dropped capabilities, seccomp, read-only root filesystem, resource limits, disabled service-account-token automounting and restricted ingress.

**Recommendation:** Pin production images by digest, deploy into a dedicated namespace and consider file-mounted secrets for additional hardening.

---

## 11. GitHub Actions use mutable references

**Severity:** Medium  
**Tool:** Semgrep (SAST)  
**Origin:** Starter CI  
**Status:** Open

Several workflow actions are referenced by mutable tags instead of immutable commit SHAs.

If an upstream action or tag is compromised, CI could execute code different from what was reviewed.

**Recommendation:** Pin security-sensitive actions to full commit SHAs and use automated dependency tooling to keep them updated.

---

## 12. Notification service findings requiring validation

**Severity:** Low / Informational  
**Tool:** Semgrep (SAST)  
**Origin:** Starter code  
**Status:** Review

Semgrep reported:

- possible mass assignment through `Object.assign()`;
- missing CSRF middleware.

These findings require context before remediation. The mass-assignment rule had low confidence, and CSRF is primarily relevant when browser credentials such as cookies are automatically attached to requests.

**Recommendation:** Review the notification route and authentication model. Implement fixes only where the behaviour is actually reachable and security-relevant.

---

## Triage Notes

Scanner output was manually reviewed rather than copied directly into this report.

- Multiple CVEs affecting the same package were grouped into dependency-level findings.
- Container CVEs were prioritised by relevance to the running application.
- The Checkov `CKV_SECRET_6` alert on `remoteSecretKey: vulntracker/prod` was treated as a false positive because it is a reference to a secret in the external secrets manager, not secret material itself.
- The Semgrep CSRF and mass-assignment results were kept at low priority pending manual validation.
- `pytest` vulnerabilities are lower production priority if test tooling is not included in the final runtime image.

---

## Remediation Priority

Remaining work should be prioritised as follows:

1. Upgrade `python-jose` and retest authentication.
2. Upgrade vulnerable cryptography and request-parsing dependencies.
3. Rebuild the container using a patched base image and rerun Grype.
4. Pin the production image by digest.
5. Deploy into a dedicated Kubernetes namespace.
6. Pin GitHub Actions to immutable commit SHAs.
7. Complete manual validation of the notification-service findings.

The highest-impact application-code issues — JWT `alg=none`, SQL injection, IDOR and plaintext password logging — were remediated in Task 3.
