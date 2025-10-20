from typing import Literal, Tuple
from datetime import datetime
import os

Decision = Literal["allow", "challenge", "deny"]
DecisionReason = Tuple[Decision, str]

# Konfiguration (über ENV anpassbar)
BH_START = int(os.getenv("BUSINESS_HOURS_START", "7"))
BH_END = int(os.getenv("BUSINESS_HOURS_END", "19"))
SENSITIVE_PATHS = set(
    p.strip() for p in os.getenv("SENSITIVE_PATHS", "/export,/admin").split(",") if p.strip()
)
REGISTERED_DEVICE_IDS = set(
    d.strip() for d in os.getenv("REGISTERED_DEVICE_IDS", "mac-001").split(",") if d.strip()
)

def _within_business_hours(now: datetime) -> bool:
    return BH_START <= now.hour <= BH_END

def evaluate_request_context(claims: dict, path: str, method: str) -> DecisionReason:
    """
    Prüft Zugriffskontext:
    1) Zeitbasiert
    2) Device-basiert
    3) Sensitivität
    Gibt (Entscheidung, Grund) zurück.
    """
    now = datetime.now()
    
    # 1) Zeitregel
    if not _within_business_hours(now):
        return "deny", f"Access denied: outside business hours ({BH_START:02d}:00–{BH_END:02d}:00)."
    
    # 2) Device-Regel
    deviceid = claims.get("deviceid")
    if not deviceid or deviceid == "unknown":
        return "deny", "Access denied: no deviceid in token."
    if deviceid not in REGISTERED_DEVICE_IDS:
        return "deny", f"Access denied: device not trusted ({deviceid})."
    
    # 3) Sensitivität
    role = claims.get("role")
    riskscore = int(claims.get("riskscore", 0))
    if path in SENSITIVE_PATHS:
        if role == "admin":
            return "allow", "Access allowed: admin on sensitive endpoint."
        if riskscore >= 70:
            return "deny", "Access denied: high riskscore on sensitive endpoint."
        return "challenge", "Access requires step-up for sensitive endpoint."
    
    return "allow", "Access allowed."
