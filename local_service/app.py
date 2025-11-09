# local_service/app.py
from fastapi import FastAPI, HTTPException, Response, Depends, Cookie
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta, timezone
import os
from jose import jwt, JWTError

APP = FastAPI(title="Local Service (Decentralised Auth)")

# --- Config (env-driven; independent from IdP) ---
LOCAL_SECRET = os.getenv("LOCAL_JWT_SECRET", "local-secret")
LOCAL_ALG = os.getenv("LOCAL_JWT_ALG", "HS256")
LOCAL_TTL = int(os.getenv("LOCAL_TOKEN_TTL_SECONDS", "60"))  # seconds
COOKIE_NAME = os.getenv("LOCAL_COOKIE_NAME", "local_session")
COOKIE_SECURE = os.getenv("LOCAL_COOKIE_SECURE", "false").lower() == "true"
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))  # container port; compose maps to 8003

# --- Minimal local user store (decentralised) ---
USERS = {
    "localuser": {"password": "local", "role": "user"},
    "localadmin": {"password": "admin", "role": "admin"},
}

class LocalLoginIn(BaseModel):
    username: str
    password: str

def _issue_local_token(sub: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": sub,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=LOCAL_TTL)).timestamp()),
        "typ": "local",            # distinguish from IdP tokens
        "iss": "local_service",    # issuer marker
    }
    # SECURITY: do not log secrets or tokens
    return jwt.encode(claims, LOCAL_SECRET, algorithm=LOCAL_ALG)

def _decode_local_token(token: str) -> dict:
    try:
        claims = jwt.decode(token, LOCAL_SECRET, algorithms=[LOCAL_ALG])
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid or expired local session: {e}")
    # optional: enforce typ/iss
    if claims.get("typ") != "local" or claims.get("iss") != "local_service":
        raise HTTPException(status_code=401, detail="Invalid local token context")
    return claims

def require_local_claims(local_session: Optional[str] = Cookie(default=None, alias=COOKIE_NAME)) -> dict:
    if not local_session:
        raise HTTPException(status_code=401, detail="Missing local session cookie")
    return _decode_local_token(local_session)

@APP.post("/local-login")
def local_login(inp: LocalLoginIn, response: Response):
    user = USERS.get(inp.username)
    if not user or user["password"] != inp.password:
        # generic error (don’t reveal which field failed)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = _issue_local_token(inp.username, user["role"])

    # Set short-lived HttpOnly cookie
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=LOCAL_TTL,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,  # set TRUE behind HTTPS in prod
        path="/",
    )
    return {"status": "ok", "message": "Local login successful", "expires_in": LOCAL_TTL}

@APP.get("/local-resource")
def local_resource(claims: dict = Depends(require_local_claims)):
    return {
        "status": "ok",
        "subject": claims.get("sub"),
        "role": claims.get("role"),
        "detail": "Access to local resource granted via local session.",
    }

@APP.get("/local-admin")
def local_admin(claims: dict = Depends(require_local_claims)):
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required for this endpoint")
    return {
        "status": "ok",
        "subject": claims.get("sub"),
        "role": claims.get("role"),
        "detail": "Admin-only local endpoint.",
    }

@APP.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:APP", host=HOST, port=PORT, reload=False)
