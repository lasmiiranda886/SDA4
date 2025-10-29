from typing import Literal, Tuple, Iterable
from datetime import datetime
import os
import zoneinfo

Decision = Literal["allow", "challenge", "deny"]
DecisionReason = Tuple[Decision, str]

# ----- Configuration via environment -----
TZ = zoneinfo.ZoneInfo(os.getenv("TZ", "Europe/Zurich"))

BH_START = int(os.getenv("BUSINESS_HOURS_START", "7"))
BH_END = int(os.getenv("BUSINESS_HOURS_END", "19"))

def _parse_csv(env_name: str, default_value: str) -> set[str]:
    raw = os.getenv(env_name, default_value)
    return {p.strip() for p in raw.split(",") if p.strip()}

SENSITIVE_PATHS = _parse_csv("SENSITIVE_PATHS", "/export,/admin,/admin/metrics")
REGISTERED_DEVICE_IDS = _parse_csv("REGISTERED_DEVICE_IDS", "mac-001,win-007,phone-123")

def _within_business_hours(now: datetime) -> bool:
    return BH_START <= now.hour < BH_END

def _is_sensitive_path(path: str, sensitive: Iterable[str]) -> bool:
    # exact match or prefix match like '/admin/...' counts as sensitive
    return any(path == p or path.startswith(p + "/") for p in sensitive)

def evaluate_request_context(path: str, claims: dict, now: datetime | None = None) -> DecisionReason:
    """
    Returns (decision, reason) where decision ∈ {"allow","challenge","deny"}.
    Policy:
      1) Deny outside business hours (Europe/Zurich).
      2) Deny if device unknown or not allow-listed.
      3) For sensitive paths:
           - admin → allow
           - non-admin & riskscore ≥ 70 → deny
           - else → challenge (step-up required)
      4) Otherwise allow.
    """
    # 1) Time-based
    now = now or datetime.now(TZ)
    if not _within_business_hours(now):
        return "deny", f"Access denied: outside business hours ({BH_START}:00–{BH_END}:00, {TZ.key})."

    # 2) Device allow-list
    deviceid = (claims.get("deviceid") or "").strip()
    if not deviceid:
        return "deny", "Access denied: device ID missing."
    if deviceid not in REGISTERED_DEVICE_IDS:
        return "deny", f"Access denied: device not trusted ({deviceid})."

    # 3) Sensitivity rules
    if _is_sensitive_path(path, SENSITIVE_PATHS):
        role = claims.get("role")
        try:
            riskscore = int(claims.get("riskscore", 0))
        except (TypeError, ValueError):
            riskscore = 0

        if role == "admin":
            return "allow", "Access allowed: admin on sensitive endpoint."
        if riskscore >= 70:
            return "deny", "Access denied: high riskscore on sensitive endpoint."
        return "challenge", "Access requires step-up for sensitive endpoint."

    # 4) Default
    return "allow", "Access allowed."
