Security Findings

Scope

This document summarizes the results of the current SAST and SCA scans for the VulnTracker application.

Tools used:

Semgrep 1.175.0 for static application security testing (SAST)

OSV-Scanner for software composition analysis (SCA)

The raw scanner output is kept separately in reports/. The findings below are manually prioritised based on the likely impact on this application rather than simply copying scanner severity.

Container and Infrastructure-as-Code findings are not included yet because those scans will be completed after the deployment artefacts are created in Task 4.

Executive Summary

The current scans identified several security issues that should be addressed before deployment.

The highest-priority issues are:

unsafe JWT validation that explicitly allows the none algorithm,

SQL injection risk in the scan search implementation,

vulnerable authentication and cryptography dependencies,

plaintext password logging,

vulnerable request parsing dependencies that may allow denial-of-service attacks.

The Semgrep scan also identified supply-chain hardening issues in GitHub Actions and lower-confidence findings in the Node.js notification service.

Prioritised Findings

#

Finding

Severity

Source

Location / Component

1

JWT validation allows the none algorithm

Critical

Semgrep

app/auth.py:38

2

SQL injection risk in scan search

Critical

Semgrep

app/database.py:28

3

Vulnerable python-jose 3.3.0

Critical

OSV-Scanner

requirements.txt

4

Vulnerable ecdsa 0.9.0

Critical

OSV-Scanner

requirements.txt

5

Vulnerable cryptography 38.0.1

High

OSV-Scanner

requirements.txt

6

Plaintext credentials written to logs

High

Semgrep

app/main.py

7

Vulnerable python-multipart 0.0.6 / FastAPI request parsing

High

OSV-Scanner

requirements.txt

8

Vulnerable starlette 0.27.0

High

OSV-Scanner

requirements.txt

9

GitHub Actions use mutable action references

Medium

Semgrep

.github/workflows/ci.yml

10

Possible mass-assignment issue in notification service

Medium / Review

Semgrep

notify/src/index.js:26

11

Missing CSRF middleware in notification service

Informational / Review

Semgrep

notify/src/index.js:6

1. JWT validation allows the none algorithm

Severity: Critical
Source: Semgrep
Location: app/auth.py:38
CWE: CWE-327

Semgrep detected that JWT validation explicitly allows the none algorithm.

Allowing none weakens the authentication boundary because tokens should only be accepted when they contain a valid cryptographic signature using an algorithm selected by the server.

Authentication protects access to vulnerability scan information, so bypassing or weakening JWT validation could allow an attacker to impersonate another user and access protected API functionality.

Recommendation

Remove none from the allowed algorithms and only accept the algorithm configured by the application.

For example:

payload = jwt.decode(
    token,
    SECRET_KEY,
    algorithms=[ALGORITHM],
)

Important JWT claims such as exp and sub should also be required and validated.

2. SQL injection risk in scan search

Severity: Critical
Source: Semgrep
Location: app/database.py:28
CWE: CWE-89

Semgrep detected the use of sqlalchemy.text() around manually constructed SQL.

In this application the search value can originate from user input, which means unsafe string construction may allow an authenticated attacker to alter the SQL statement.

Because VulnTracker stores security findings, successful SQL injection could expose scan records belonging to other users or otherwise compromise database confidentiality, integrity or availability.

Recommendation

Replace dynamically constructed SQL with SQLAlchemy ORM expressions or bound parameters.

For example, prefer:

db.query(models.ScanResult).filter(
    models.ScanResult.title.ilike(search_term)
)

rather than interpolating the search value directly into SQL text.

3. Vulnerable python-jose 3.3.0

Severity: Critical
Source: OSV-Scanner
Package: python-jose==3.3.0

OSV-Scanner identified multiple advisories affecting the installed version of python-jose.

The highest-severity reported issue is:

CVE-2024-33663 / GHSA-6c5p-j8vq-pqhj

reported maximum severity: 9.3

affected versions include python-jose through 3.3.0

fixed in version 3.4.0

The advisory describes an algorithm-confusion issue involving OpenSSH ECDSA keys and other key formats.

This finding is especially relevant because python-jose is used by the application's authentication code.

Recommendation

Upgrade python-jose to at least a version containing the fix and retest authentication behaviour.

The code-level JWT fix described in Finding 1 should still be applied; upgrading the dependency does not replace secure JWT configuration.

4. Vulnerable ecdsa 0.9.0

Severity: Critical
Source: OSV-Scanner
Package: ecdsa==0.9.0

OSV-Scanner reported multiple vulnerabilities affecting the installed ecdsa version, with a maximum reported severity of 9.3.

Examples in the scanner result include:

CVE-2019-14853

CVE-2019-14859

CVE-2024-23342

CVE-2026-33936

Since this dependency is cryptography-related and may be used through JWT functionality, it should not remain pinned to this outdated version without a specific compatibility requirement.

Recommendation

Upgrade to a current supported version compatible with the JWT library, then run the test suite and repeat the SCA scan.

5. Vulnerable cryptography 38.0.1

Severity: High
Source: OSV-Scanner
Package: cryptography==38.0.1

OSV-Scanner reported a large number of advisories for cryptography 38.0.1.

Examples include:

CVE-2023-23931

CVE-2023-49083

CVE-2024-26130

CVE-2023-50782

CVE-2024-0727

The highest scanner severity associated with this installed version is 8.7.

Not every advisory is necessarily reachable through VulnTracker, but the package performs security-sensitive cryptographic operations and the installed version is significantly behind current patched releases.

Recommendation

Upgrade cryptography to a supported patched version and verify compatibility with authentication and password-handling dependencies.

6. Plaintext credentials written to application logs

Severity: High
Source: Semgrep
Location: app/main.py:184, app/main.py:187-191
CWE: CWE-532

Semgrep detected that the login flow writes submitted passwords to application logs.

Passwords should never be included in log messages. Logs are commonly forwarded to centralized platforms and retained for long periods, which would turn the logging system into another source of reusable credentials.

Failed login logging is particularly risky because users can accidentally enter a password that belongs to another account.

Semgrep also flagged logging around failed password attempts for the Task 1 share-link functionality at approximately app/main.py:431-436. The log message should be reviewed so that no password, raw share token, or other reusable secret is recorded.

Recommendation

Remove passwords and reusable secrets from all log messages.

Logging the username, event type, timestamp, request identifier, and success/failure status is normally sufficient for security monitoring.

7. Vulnerable python-multipart 0.0.6 and request parsing

Severity: High
Source: OSV-Scanner
Package: python-multipart==0.0.6

OSV-Scanner identified multiple vulnerabilities affecting the installed version of python-multipart.

Relevant examples include:

CVE-2024-24762 — Content-Type parsing ReDoS

CVE-2024-53981

CVE-2026-24486

CVE-2026-53539 — quadratic-time query-string parsing

CVE-2026-40347 — excessive processing of multipart preamble/epilogue

Several of these issues can result in excessive CPU usage or denial of service while processing crafted request bodies.

This is relevant to a FastAPI application because form and multipart parsing may occur before endpoint logic completes.

The OSV result for the quadratic query-string parsing issue states that it is fixed in python-multipart 0.0.30 or later.

Recommendation

Upgrade python-multipart to a patched supported version and retest endpoints that process form or multipart data.

Request-size limits and upstream rate limiting should also be used as defence in depth.

8. Vulnerable starlette 0.27.0

Severity: High
Source: OSV-Scanner
Package: starlette==0.27.0

OSV-Scanner reported several vulnerabilities affecting the installed Starlette version, with a maximum reported severity of 8.7.

Starlette is part of the underlying request-handling stack used by FastAPI, so issues in this dependency can affect externally reachable HTTP behaviour even if the application does not import the vulnerable functionality directly.

Recommendation

Upgrade FastAPI and Starlette together to compatible supported versions rather than changing Starlette independently without checking framework compatibility.

Repeat application tests and the SCA scan after the upgrade.

9. GitHub Actions are not pinned to immutable commit SHAs

Severity: Medium
Source: Semgrep
Location: .github/workflows/ci.yml:14, 17, 31, 34
CWE: CWE-1357 / CWE-353

Semgrep identified four GitHub Actions references that use mutable tags or branches.

A tag such as @v4 is easier to maintain, but it can theoretically be moved to different code. If an action or upstream account is compromised, this can increase CI/CD supply-chain risk.

Recommendation

For security-sensitive workflows, pin third-party actions to full commit SHAs and use automated dependency tooling to keep those pins updated.

The four Semgrep alerts are treated as one finding because they represent the same underlying configuration issue.

10. Possible mass-assignment issue in the notification service

Severity: Medium / Requires manual validation
Source: Semgrep
Location: notify/src/index.js:26
CWE: CWE-915

Semgrep flagged the use of user-controlled data with Object.assign().

Depending on which properties are accepted and how the resulting object is used, an attacker may be able to set fields that were not intended to be externally controlled.

Semgrep reported low confidence for this result, so it should not automatically be treated as a confirmed exploitable vulnerability.

Recommendation

Review the route and replace unrestricted object copying with an explicit allowlist of accepted properties where possible.

11. Missing CSRF middleware in the notification service

Severity: Informational / Requires manual validation
Source: Semgrep
Location: notify/src/index.js:6
CWE: CWE-352

Semgrep did not detect CSRF middleware in the Express service.

This is not automatically a vulnerability. CSRF is mainly relevant when browsers automatically attach authentication credentials, such as session cookies, to cross-origin requests.

If this notification service is authenticated only with an API key supplied explicitly by another backend service, the missing CSRF middleware may not be exploitable.

Recommendation

Confirm the authentication model before remediation.

If the service uses browser-based cookie authentication, implement appropriate CSRF controls. Otherwise this finding can be documented as not applicable.

Additional SCA Findings

The OSV scan also reported vulnerabilities affecting:

fastapi==0.104.1

idna==3.9.0

pytest==7.4.3

fastapi==0.104.1 is associated with the request parsing / ReDoS issue also represented through python-multipart, so it is not treated as a separate top-priority application finding above.

pytest is primarily a development/testing dependency, so its production impact is lower unless it is included in the production runtime image.

These packages should still be upgraded to currently supported versions where compatibility allows.