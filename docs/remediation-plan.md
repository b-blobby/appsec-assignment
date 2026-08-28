H1 — Hardcoded secrets in app/config.py and notify/src/config.js

Residual risk: High. SECRET_KEY signs the JWTs, so anyone with repository access can forge properly signed tokens — meaning fix 1 alone does not fully restore authentication integrity. ADMIN_API_KEY is named as a production key.

Why deferred: the code change is small, but it is the visible half of the work. These values are in git history, so they are already disclosed to everyone who has ever cloned this repository, and deleting them from a file is not remediation — they must be rotated at source. That is an operational process involving whoever owns the database and the internal API, not a code edit. The code change also properly belongs with Task 4, where the deployment gains a secrets manager to read from; moving to environment variables first would just relocate the secret rather than protect it.

Effort: ~1 hour for the code (environment sourcing plus fail-closed startup check), plus credential rotation coordinated with the service owners.

Compensating controls: none meaningful. This is the highest-priority remaining item.

H5 — Stack traces returned to clients

Residual risk: High. The global handler returns traceback.format_exc(), and notify returns err.stack. This matters more since Task 1, because GET /share/{token} is the application's first public, unauthenticated endpoint: an unhandled error there hands file paths and dependency versions to an anonymous caller.

Why deferred: a genuine judgement call, and the one I am least comfortable with. It is roughly a 10-line change. I ranked it below fixes 1–4 because it discloses information that accelerates an attack rather than granting access by itself, and the accesses it would accelerate are now closed. If a fifth fix were in scope, this is it.

Effort: ~30 minutes including a test.

Compensating control: the share endpoint validates its inputs (token length capped, password length capped) so the common paths into an unhandled exception are narrow.

H8 — Reflective CORS policy with credentials

Residual risk: High if session cookies are ever introduced; Medium today. The middleware echoes any Origin and sets Allow-Credentials: true, which is equivalent to having no same-origin policy.

Why deferred: the fix is an allowlist, and I do not know what belongs on it. The repository contains no frontend and the brief names no origins, so any list I wrote would be a guess — and a guessed CORS allowlist either breaks a real client or silently keeps the hole open. This needs an answer from whoever owns the UI, not a default I invented.

Effort: ~15 minutes once the trusted origins are known.

Compensating control: authentication is bearer-token-based, not cookie-based, so a browser does not automatically attach credentials cross-origin today. This is why the practical severity is currently lower than the finding suggests — and exactly why the middleware must be fixed before any move to cookie sessions.

C3 — Unauthenticated webhook registration, SSRF, service-key disclosure

Residual risk: Critical. Anyone who can reach port 3001 registers a webhook, receives a live feed of every scan event plus the X-Service-Key header, and gains an SSRF primitive that reaches cloud instance metadata once deployed.

Why deferred: the submission brief states notify/ requires no changes, so I have not unilaterally rewritten a component declared out of scope. This is a scope decision, not a risk judgement. In a real service I would treat C3 as a release blocker and fix it before C1.

Effort: ~4 hours. Authenticate POST /webhooks; validate destinations against an allowlist rejecting private, loopback and link-local ranges after DNS resolution and on every redirect hop, or the check is bypassable by DNS rebinding; and replace the shared header with an HMAC signature over the body so recipients can verify authenticity without receiving a reusable credential.

Compensating control: the Task 4 NetworkPolicy restricts ingress to notify so only the API pod can reach it, and restricts egress so the pod cannot reach the metadata endpoint. That reduces the attack from "anyone on the network" to "anyone with a foothold in the cluster" — real, but not a substitute for the code fix.

H6 — python-jose 3.3.0 CVEs

Residual risk: High, sharply reduced by fix 1. Algorithm confusion (PYSEC-2024-232) requires influencing algorithm selection, which pinning now prevents. The JWT-bomb DoS (PYSEC-2024-233) remains reachable unauthenticated.

Why deferred, and why not simply upgrade: 3.4.0 fixes two of three advisories. PYSEC-2025-185 has no fixed version at all, so upgrading leaves a known unpatched CVE in the authentication path indefinitely. The right move is migration to PyJWT, which is a decision worth making deliberately rather than bolting onto this PR.

Effort: ~2 hours — two call sites (create_access_token, decode_token) plus tests. Also removes the ecdsa transitive dependency, resolving L1.

Compensating controls: algorithm pinning (fix 1); 30-minute token lifetime.

H7 / M3 — axios 0.21.1 and the Express dependency chain

Deferred with the rest of notify/. Residual risk High for axios (it amplifies C3), Medium for Express (ReDoS, availability only). Effort ~1 hour for the bumps, but axios 0.21 → 1.x is a major version with breaking changes to error handling and request config, so the real cost is regression-testing the dispatcher. Compensating control: the 5-second dispatch timeout caps slow-response impact; NetworkPolicy egress limits SSRF reach.

M1 — No rate limiting on POST /auth/login

Residual risk: Medium. Unlimited credential stuffing, no lockout, no MFA.

Why deferred: an in-process counter is close to useless behind more than one replica, so this needs shared state (Redis-backed slowapi) or enforcement at the ingress/WAF layer. Choosing where it lives is an architecture decision.

Effort: ~3 hours done properly.

Compensating controls: bcrypt imposes real cost per attempt; fix 4 means failed-login lines are now safe to ship to a SIEM and alert on. Note the contrast — the Task 1 share endpoint does implement a persistent lockout after 10 failed attempts. The same approach is not blindly transferable to login, because a naive account lockout is itself a denial-of-service vector against named users.

M2 / M5 — cryptography 38.0.1, python-multipart 0.0.6

Residual risk: Low in practice. The cryptography advisories concentrate in X.509 and SSH code paths this application never executes; it is used only indirectly for HMAC. No route accepts multipart uploads, so that parser is unreachable from application code.

Why deferred: cryptography is the largest number in the SCA report and one of the smallest real risks. Fixing it first would be optimising for a dashboard. Bundle both with the H6 migration. Effort: ~45 minutes combined.

M4 — Unbounded in-memory webhook registry

Deferred with notify/. Residual risk Medium (memory-exhaustion DoS, compounded by C3's missing auth). A size cap is ~1 hour, but the registry should move to persistent storage anyway — registrations are currently lost on every restart — making a proper fix ~1 day. Compensating control: container memory limits in the Task 4 manifests turn an unbounded leak into a pod restart rather than a node outage.

L1 — ecdsa 0.19.2 timing side-channel, no fix available

Accepted. Tokens are signed with HS256, so the vulnerable ECDSA path never executes, and the package is only a transitive dependency of python-jose. No upstream fix exists, so the only remediation is removal — which happens automatically when H6 is resolved.