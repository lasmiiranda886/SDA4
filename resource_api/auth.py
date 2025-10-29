from fastapi import HTTPException, Header
from jose import jwt, JWTError
import os

# Read verification settings from environment (shared with IdP)
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-idp")
JWT_ALG = os.getenv("JWT_ALG", "HS256")

def get_claims(authorization: str = Header(..., alias="Authorization")) -> dict:
    """
    Strict 'Authorization: Bearer <token>' parsing and JWT verification.
    No logging of secrets or tokens.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token in Authorization header")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty bearer token")

    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token invalid: {e}")
    return claims
