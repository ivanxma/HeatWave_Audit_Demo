"""Safe, actionable error explanations without echoing server-provided secrets."""

import re


def audit_server_reason(exc, sensitive_values=()):
    """Only expose the audit UDF's reason; redact quoted values and server paths."""
    raw = str(getattr(exc, "msg", "") or "")
    match = re.search(
        r"\baudit_log_read(?:_bookmark)? UDF failed;\s*(.*)", raw, re.I | re.S
    )
    if not match:
        return ""
    reason = match.group(1)
    for value in sensitive_values:
        if value:
            reason = reason.replace(str(value), "[redacted]")
    reason = re.sub(
        r"(?i)(password|passwd|secret|token|credential)\s*[:=]\s*[^\s;]+",
        r"\1=[redacted]",
        reason,
    )
    reason = re.sub(r"(['\"])(.*?)\1", "[quoted value]", reason)
    reason = re.sub(r"(?<!\w)(?:/[\w.~-]+){2,}(?:/[\w.~-]*)?", "[server path]", reason)
    return " ".join(reason.split())[:512]


def _explanation(exc):
    code = getattr(exc, "errno", None)
    if code == 3200:
        reason = str(getattr(exc, "msg", "") or "").lower()
        if "reader not initialized" in reason:
            return (
                "Audit reader is not initialized or has reached the end of the log (MySQL 3200). "
                "Start a new read using a timestamp or bookmark. For an existing audit view, "
                "replace its definition with the current builder SQL before retrying."
            )
        if "wrong argument format" in reason or "invalid json" in reason:
            return (
                "Audit reader rejected the JSON argument format (MySQL 3200). "
                "Replace the existing view using the current builder SQL, which passes JSON text, "
                "or try a direct timestamp read in Log reader."
            )
        if "json" in reason and "format" in reason:
            return "Audit reader requires JSON audit log format (MySQL 3200). Inspect audit_log_format."
        return (
            "Audit function failed (MySQL 3200). This code wraps a server-side UDF error; "
            "it does not identify a column mapping problem. Inspect audit variables and the audit server reason shown above."
        )
    return (
        f"MySQL rejected the operation{f' (code {code})' if code else ''}. "
        "Check audit availability, JSON format, privileges and selected database. "
        "Earlier statements may have completed; inspect the server before retrying."
    )


def mysql_error_message(exc, sensitive_values=()):
    explanation = _explanation(exc)
    if getattr(exc, "errno", None) == 3200:
        reason = audit_server_reason(exc, sensitive_values)
        if reason:
            explanation = f"Audit server error (MySQL 3200): {reason}. " + explanation
    step = getattr(exc, "audit_statement_index", None)
    total = getattr(exc, "audit_statement_count", None)
    if step:
        explanation = f"Statement {step} of {total} failed. " + explanation
    return explanation
