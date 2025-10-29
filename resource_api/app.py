from fastapi import FastAPI, Depends, HTTPException, Request
from auth import get_claims
from context import evaluate_request_context

APP = FastAPI(title="Resource API")

def _apply_context(request: Request, claims: dict):
    path = request.url.path
    decision, reason = evaluate_request_context(path, claims)

    if decision == "deny":
        raise HTTPException(status_code=403, detail=reason)
    if decision == "challenge":
        return {"status": "mfa_required", "reason": reason}
    # decision == "allow"
    return {
        "status": "ok",
        "subject": claims.get("sub"),
        "role": claims.get("role"),
        "path": path,
        "reason": reason,
    }

@APP.get("/health")
def health():
    return {"status": "ok"}

@APP.get("/resource")
def resource(req: Request, claims: dict = Depends(get_claims)):
    """Non-sensitive example endpoint."""
    return _apply_context(req, claims)

@APP.get("/export")
def export(req: Request, claims: dict = Depends(get_claims)):
    """Sensitive endpoint — will trigger step-up/deny for non-admins based on risk."""
    return _apply_context(req, claims)

@APP.get("/admin/metrics")
def admin_metrics(req: Request, claims: dict = Depends(get_claims)):
    """Another sensitive endpoint (admin allowed, others challenge/deny)."""
    return _apply_context(req, claims)
