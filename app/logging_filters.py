"""FIX 4 (H3 + H4, High): keep credentials out of logs.

Two instances of the same defect:

* `POST /auth/login` logged `payload.password` in cleartext on every attempt.
* `GET /share/{token}?password=...` is logged in full by uvicorn's access
  logger, so both the share token and its password land in the access log.
  Confirmed during testing:

      INFO: 127.0.0.1 - "GET /share/FwNl7zg...?password=auditor-pass-2026" 200 OK

The login call site is fixed directly in main.py. The share endpoint cannot be
fixed that way — the brief specifies the `password` query parameter, so the
endpoint must keep accepting it. This filter scrubs the value out of every log
record instead.

This is a mitigation, not a cure: the credential is still in the URL and may be
recorded by proxies and CDNs upstream. The complete fix is the
X-Share-Password header, which the endpoint already prefers.
"""

import logging
import re

REDACTED = "[REDACTED]"

# secret=value in a query string, up to the next & or whitespace.
_QUERY_SECRET = re.compile(
    r"(?i)\b(password|passwd|pw|secret|token|api_key|apikey)=([^&\s\"']+)"
)

# The share token is itself a bearer credential. A short prefix is kept so log
# entries can still be correlated with the share_links table during an incident.
_SHARE_PATH = re.compile(r"(/share/)([A-Za-z0-9_\-]{8})[A-Za-z0-9_\-]+")


def scrub(value: str) -> str:
    value = _QUERY_SECRET.sub(rf"\1={REDACTED}", value)
    return _SHARE_PATH.sub(r"\1\2...", value)


class RedactSecretsFilter(logging.Filter):
    """Rewrites secrets out of records before they are emitted.

    uvicorn.access passes the request line through record.args as a tuple
    (client, method, path, http_version, status), so args are scrubbed as well
    as the message itself.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(
                scrub(a) if isinstance(a, str) else a for a in record.args
            )
        if isinstance(record.msg, str):
            record.msg = scrub(record.msg)
        return True  # never drop a record, only sanitise it


def install() -> None:
    """Attach the filter to the loggers and handlers that see request data."""
    redactor = RedactSecretsFilter()
    for name in ("", "uvicorn.access", "uvicorn.error"):
        log = logging.getLogger(name)
        log.addFilter(redactor)
        # Handlers are filtered too: a filter on a logger does not apply to
        # records propagated up from its children.
        for handler in log.handlers:
            handler.addFilter(redactor)