from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import jwt
import os

APP = FastAPI(title="Identity Provider")

JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")
JWT_ALG = os.getenv("JWT_ALG", "HS256")

# Beispiel-Userdatenbank
USERS = {
    "analyst": {"password": "analyst", "role": "analyst"},
    "contractor": {"password": "contractor", "role": "contractor"},
    "admin": {"password": "admin", "role": "admin"},
}

class LoginIn(BaseModel):
    username: str
    password: str
    device_id: str | None = None
    deviceid: str | None = None

@APP.post("/login")
def login(inp: LoginIn):
    u = USERS.get(inp.username)
    if not u or u["password"] != inp.password:
        raise HTTPException(status_code=401, detail="invalid credentials")

    now = datetime.now(timezone.utc)
    dev = inp.deviceid or inp.device_id

    # Risiko-Policy: contractor = höheres Risiko
    base_risk = 70 if u["role"] == "contractor" else 30
    if not dev:
        base_risk += 20  # Kein Device => Risiko höher

    claims = {
        "sub": inp.username,
        "role": u["role"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
        "typ": "access",
        "deviceid": dev or "unknown",
        "riskscore": base_risk,
        "auth_time": int(now.timestamp()),
    }

    token = jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALG)
    return {"access_token": token, "token_type": "bearer"}
