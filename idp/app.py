# idp/app.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import os
import jwt  # PyJWT
from typing import Optional

APP = FastAPI(title="Identity Provider (IdP)")

# --- Config from environment (see idp/.env) ---
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-idp")
JWT_ALG = os.getenv("JWT_ALG", "HS256")
TOKEN_EXP_MINUTES = int(os.getenv("TOKEN_EXP_MINUTES", "30"))

# Optional for local run via `python idp/app.py` (Docker usually starts uvicorn itself)
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

# --- Minimal demo user store (didactic only) ---
USERS = {
    os.getenv("USER_ANALYST", "analyst"): {
        "password": os.getenv("PASSWORD_ANALYST", "analyst"),
        "role": "analyst",
    },
    os.getenv("USER_CONTRACTOR", "contractor"): {
        "password": os.getenv("PASSWORD_CONTRACTOR", "contractor"),
        "role": "contractor",
    },
    # keep an admin for sensitive-route tests
    "admin": {"password": "admin", "role": "admin"},
}

class LoginIn(BaseModel):
    username: str
    password: str
    deviceid: Optional[str] = None
    device_id: Optional[str] = None  # accept alternate field name

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds

def compute_risk(role: str, deviceid: str) -> int:
    """
    Simple illustrative risk scoring:
      - contractors carry higher baseline risk (+20)
      - missing/unknown device adds risk (+20)
    """
    risk = 40
    if role == "contractor":
        risk += 20
    if not deviceid or deviceid.strip().lower() in {"", "unknown", "none"}:
        risk += 20
    return max(0, min(risk, 99))

@APP.post("/login", response_model=TokenOut)
def login(inp: LoginIn):
    # authenticate
    user = USERS.get(inp.username)
    if not user or user["password"] != inp.password:
        # generic error to avoid hinting which field failed
        raise HTTPException(status_code=401, detail="Invalid credentials")

    role = user["role"]
    deviceid = (inp.deviceid or inp.device_id or "unknown").strip() or "unknown"

    now = datetime.now(timezone.utc)
    iat = int(now.timestamp())
    exp_dt = now + timedelta(minutes=TOKEN_EXP_MINUTES)
    exp = int(exp_dt.timestamp())
    auth_time = iat

    riskscore = compute_risk(role, deviceid)

    # Required claims per assignment
    claims = {
        "sub": inp.username,
        "role": role,
        "deviceid": deviceid,
        "riskscore": riskscore,
        "iat": iat,
        "exp": exp,
        "typ": "access",
        "auth_time": auth_time,
    }

    token = jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALG)

    # SECURITY: do not print/log secrets, tokens, or full claims.
    return TokenOut(access_token=token, expires_in=exp - iat)

@APP.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    # Optional local run: `python idp/app.py` (Docker usually runs uvicorn externally)
    import uvicorn
    uvicorn.run("app:APP", host=HOST, port=PORT, reload=False)
