from fastapi import FastAPI, Depends, HTTPException
from auth import get_claims
from context import evaluate_request_context

APP = FastAPI(title="Resource API")

@APP.get("/resource")
def resource(claims: dict = Depends(get_claims)):
    decision, reason = evaluate_request_context(claims, "/resource", "GET")
    if decision == "deny":
        raise HTTPException(status_code=403, detail=reason)
    if decision == "challenge":
        return {"status": "mfa_required", "reason": reason}
    return {"status": "ok", "reason": reason, "subject": claims.get("sub"), "role": claims.get("role")}

@APP.get("/export")
def export(claims: dict = Depends(get_claims)):
    decision, reason = evaluate_request_context(claims, "/export", "GET")
    if decision == "deny":
        raise HTTPException(status_code=403, detail=reason)
    if decision == "challenge":
        return {"status": "mfa_required", "reason": reason}
    return {"status": "export_ready", "reason": reason}
