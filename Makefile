# Makefile -- Demo flows for SDA4 Zero Trust assignment (teaching-friendly)
# Usage:
#   make help
#   make up
#   make demo-all        # quick
#   make demo-narrated   # narrated & with JWT inspection

SHELL := /bin/bash
.ONESHELL:
.SILENT:

IDP := http://localhost:8001
RES := http://localhost:8002
LOC := http://localhost:8003
TMP := .tmp

CURL := curl -sS
JQ := jq -r

.PHONY: help
help:
	echo "Targets:"
	echo "  up / down / logs / clean"
	echo "  demo-all              Run all scenarios (fast)"
	echo "  demo-narrated         Run all scenarios with explanations & JWT inspection"
	echo "  demo-local-expiry     Show local cookie expires after ~60s"
	echo "  inspect-token-analyst Show IdP JWT payload for analyst"
	echo "  inspect-token-admin   Show IdP JWT payload for admin"
	echo "  print-config          Show effective env config of services"
	echo "  offhours-note         How to trigger off-hours deny"
	echo "  ...and all previous fine-grained targets (login-*, call-*, local-*)"

# --- Orchestration ------------------------------------------------------------

.PHONY: up
up: deps
	mkdir -p $(TMP)
	docker compose up --build -d
	echo "Services up:"
	echo "  IdP          $(IDP)"
	echo "  Resource API $(RES)"
	echo "  Local        $(LOC)"
	$(MAKE) wait-all

.PHONY: down
down:
	docker compose down -v

.PHONY: logs
logs:
	docker compose logs -f --tail=100

.PHONY: deps
deps:
	command -v curl >/dev/null || (echo "curl missing"; exit 1)
	command -v jq >/dev/null || (echo "jq missing"; exit 1)
	command -v base64 >/dev/null || (echo "base64 missing"; exit 1)

# --- Wait for services to be ready -------------------------------------------

.PHONY: wait-idp wait-resource wait-local wait-all
wait-idp:
	echo "Waiting for IdP ..."
	for i in {1..40}; do \
	  if $(CURL) $(IDP)/health >/dev/null; then echo "IdP ready"; exit 0; fi; \
	  sleep 0.5; \
	done; echo "IdP not ready"; exit 1

wait-resource:
	echo "Waiting for Resource API ..."
	for i in {1..40}; do \
	  if $(CURL) $(RES)/health >/dev/null; then echo "Resource API ready"; exit 0; fi; \
	  sleep 0.5; \
	done; echo "Resource API not ready"; exit 1

wait-local:
	echo "Waiting for Local Service ..."
	for i in {1..40}; do \
	  if $(CURL) $(LOC)/health >/dev/null; then echo "Local Service ready"; exit 0; fi; \
	  sleep 0.5; \
	done; echo "Local Service not ready"; exit 1

wait-all: wait-idp wait-resource wait-local

# --- helper: robust JSON login with retries & debug ---------------------------
# Usage: $(call LOGIN_JSON,username,password,deviceid,outfile)
define LOGIN_JSON
	mkdir -p $(TMP); \
	USER="$(1)"; PASS="$(2)"; DEV="$(3)"; OUT="$(4)"; \
	for i in 1 2 3 4 5; do \
	  DATA=$$(jq -n --arg u "$$USER" --arg p "$$PASS" --arg d "$$DEV" \
	    '{username:$$u,password:$$p} + (if $$d=="" then {} else {device_id:$$d} end)'); \
	  RESP=$$($(CURL) -w "\n%{http_code}" -X POST $(IDP)/login \
	    -H 'Content-Type: application/json' --data "$$DATA"); \
	  BODY=$$(printf "%s" "$$RESP" | sed '$$d'); \
	  CODE=$$(printf "%s" "$$RESP" | tail -n1); \
	  if [ "$$CODE" = "200" ]; then \
	    TOKEN=$$(printf "%s" "$$BODY" | jq -r '.access_token'); \
	    if [ "$$TOKEN" != "null" ] && [ -n "$$TOKEN" ]; then \
	      printf "%s" "$$TOKEN" > "$$OUT"; echo "Saved token -> $$OUT"; exit 0; \
	    fi; \
	  fi; \
	  echo "Login attempt $$i failed (HTTP $$CODE): $$BODY"; sleep 1; \
	done; echo "Login failed after 5 attempts"; exit 1
endef

# --- helper: decode JWT payload (base64url portable) --------------------------
# Usage: $(call SHOW_JWT_FILE,.tmp/analyst.token)
define SHOW_JWT_FILE
	if [ ! -f "$(1)" ]; then echo "Token file not found: $(1)"; exit 1; fi; \
	TOKEN=$$(cat "$(1)"); \
	PAY=$$(echo "$$TOKEN" | cut -d. -f2 | tr '_-' '/+'); \
	PAD=$$(( (4 - $${#PAY}%4) %4 )); \
	if [ $$PAD -gt 0 ]; then PAY="$$PAY$$(printf '=%.0s' $$(seq 1 $$PAD))"; fi; \
	( echo "$$PAY" | base64 -d 2>/dev/null || echo "$$PAY" | base64 -D 2>/dev/null ) | jq .
endef

# --- IdP logins (centralised) ------------------------------------------------

.PHONY: login-analyst
login-analyst: deps wait-idp
	@$(call LOGIN_JSON,analyst,analyst,mac-001,$(TMP)/analyst.token)

.PHONY: login-admin
login-admin: deps wait-idp
	@$(call LOGIN_JSON,admin,admin,mac-001,$(TMP)/admin.token)

.PHONY: login-analyst-rogue
login-analyst-rogue: deps wait-idp
	@$(call LOGIN_JSON,analyst,analyst,rogue-999,$(TMP)/analyst-rogue.token)

.PHONY: login-analyst-nodevice
login-analyst-nodevice: deps wait-idp
	@$(call LOGIN_JSON,analyst,analyst,,$(TMP)/analyst-nodevice.token)

# --- JWT inspection (NEW) -----------------------------------------------------

.PHONY: inspect-token-analyst inspect-token-admin inspect-token-rogue inspect-token-nodevice
inspect-token-analyst: login-analyst
	echo "JWT payload (analyst, registered device):"
	@$(call SHOW_JWT_FILE,$(TMP)/analyst.token)

inspect-token-admin: login-admin
	echo "JWT payload (admin, registered device):"
	@$(call SHOW_JWT_FILE,$(TMP)/admin.token)

inspect-token-rogue: login-analyst-rogue
	echo "JWT payload (analyst, rogue device):"
	@$(call SHOW_JWT_FILE,$(TMP)/analyst-rogue.token)

inspect-token-nodevice: login-analyst-nodevice
	echo "JWT payload (analyst, missing device):"
	@$(call SHOW_JWT_FILE,$(TMP)/analyst-nodevice.token)

# --- Resource API calls (centralised) ----------------------------------------

define _bearer
-H "Authorization: Bearer $$(cat $(1))"
endef

.PHONY: call-resource-allow
call-resource-allow: login-analyst wait-resource
	echo "Expect ALLOW (business hours, registered device)"
	$(CURL) $(RES)/resource $(call _bearer,$(TMP)/analyst.token) | jq .

.PHONY: call-export-challenge
call-export-challenge: login-analyst wait-resource
	echo "Expect CHALLENGE (sensitive endpoint, non-admin)"
	$(CURL) $(RES)/export $(call _bearer,$(TMP)/analyst.token) | jq .

.PHONY: call-export-admin
call-export-admin: login-admin wait-resource
	echo "Expect ALLOW (sensitive endpoint, admin)"
	$(CURL) $(RES)/export $(call _bearer,$(TMP)/admin.token) | jq .

.PHONY: call-resource-deny-unknown-device
call-resource-deny-unknown-device: login-analyst-rogue wait-resource
	echo "Expect DENY (device not trusted)"; \
	$(CURL) -w "\nHTTP %{http_code}\n" -o /dev/null $(RES)/resource $(call _bearer,$(TMP)/analyst-rogue.token); \
	$(CURL) $(RES)/resource $(call _bearer,$(TMP)/analyst-rogue.token) | jq .

.PHONY: call-resource-deny-missing-device
call-resource-deny-missing-device: login-analyst-nodevice wait-resource
	echo "Expect DENY (device not trusted / missing)"; \
	$(CURL) -w "\nHTTP %{http_code}\n" -o /dev/null $(RES)/resource $(call _bearer,$(TMP)/analyst-nodevice.token); \
	$(CURL) $(RES)/resource $(call _bearer,$(TMP)/analyst-nodevice.token) | jq .

.PHONY: offhours-note
offhours-note:
	echo "To see off-hours denial, run after local business hours (07:00-19:00 Europe/Zurich)."
	echo "Alternatively, temporarily set BUSINESS_HOURS_END=0 in resource_api/.env and restart the service."

# --- Local Service cookie flow (decentralised) --------------------------------

.PHONY: local-login-user
local-login-user: deps wait-local
	mkdir -p $(TMP)
	$(CURL) -X POST $(LOC)/local-login -H 'Content-Type: application/json' \
	  -d '{"username":"localuser","password":"local"}' -c $(TMP)/local_user.cookies | jq .
	echo "Cookie jar saved -> $(TMP)/local_user.cookies"

.PHONY: local-login-admin
local-login-admin: deps wait-local
	mkdir -p $(TMP)
	$(CURL) -X POST $(LOC)/local-login -H 'Content-Type: application/json' \
	  -d '{"username":"localadmin","password":"admin"}' -c $(TMP)/local_admin.cookies | jq .
	echo "Cookie jar saved -> $(TMP)/local_admin.cookies"

.PHONY: local-user-resource
local-user-resource: local-login-user wait-local
	$(CURL) $(LOC)/local-resource -b $(TMP)/local_user.cookies | jq .

.PHONY: local-user-admin
local-user-admin: local-login-user wait-local
	echo "Expect 403 (user is not admin) -- show HTTP code then JSON body"
	$(CURL) -w "\nHTTP %{http_code}\n" -o /dev/null $(LOC)/local-admin -b $(TMP)/local_user.cookies
	$(CURL) $(LOC)/local-admin -b $(TMP)/local_user.cookies | jq .

.PHONY: local-admin-admin
local-admin-admin: local-login-admin wait-local
	echo "Expect 200 (admin)"
	$(CURL) $(LOC)/local-admin -b $(TMP)/local_admin.cookies | jq .

# --- Config introspection (NEW) -----------------------------------------------

.PHONY: print-config
print-config:
	echo "=== Resource API policy-related env ==="
	docker compose exec -T resource_api env | egrep 'JWT_SECRET|JWT_ALG|BUSINESS_HOURS|REGISTERED_DEVICE_IDS|SENSITIVE_PATHS|TZ' || true
	echo "=== IdP token config ==="
	docker compose exec -T idp env | egrep 'JWT_SECRET|JWT_ALG|TOKEN_EXP_MINUTES' || true
	echo "=== Local Service env ==="
	docker compose exec -T local_service env | egrep 'LOCAL_JWT_SECRET|LOCAL_JWT_ALG|LOCAL_TOKEN_TTL_SECONDS' || true

# --- Rollups ------------------------------------------------------------------

.PHONY: demo-centralised
demo-centralised: call-resource-allow call-export-challenge call-export-admin call-resource-deny-unknown-device call-resource-deny-missing-device

.PHONY: demo-local
demo-local: local-user-resource local-user-admin local-admin-admin

# NEW: Narrated demo (explains + inspects JWTs)
.PHONY: demo-narrated
demo-narrated: up wait-all
	echo "-- Centralised flow: login as ANALYST (registered device) --"
	$(MAKE) inspect-token-analyst
	echo "Now call /resource -> should ALLOW due to business hours + trusted device."
	$(MAKE) call-resource-allow
	echo "Now call /export -> non-admin on sensitive path -> CHALLENGE (mfa_required)."
	$(MAKE) call-export-challenge
	echo "-- Login as ADMIN and call /export -> should ALLOW on sensitive path --"
	$(MAKE) inspect-token-admin
	$(MAKE) call-export-admin
	echo "-- Device trust checks -> DENY for rogue/missing device --"
	$(MAKE) call-resource-deny-unknown-device
	$(MAKE) call-resource-deny-missing-device
	echo "-- Decentralised flow (Local Service) --"
	$(MAKE) local-user-resource
	$(MAKE) local-user-admin
	$(MAKE) local-admin-admin
	echo "-- Config sanity (optional) --"
	$(MAKE) print-config

# NEW: Expiry proof for local cookie (expects LOCAL_TOKEN_TTL_SECONDS=60)
.PHONY: demo-local-expiry
demo-local-expiry: wait-local
	echo "Local login (should print expires_in: 60) ..."
	$(CURL) -X POST $(LOC)/local-login \
	  -H 'Content-Type: application/json' \
	  -d '{"username":"localuser","password":"local"}' \
	  -c $(TMP)/local_user.cookies | jq .
	echo "Immediate call to /local-resource (should be OK):"
	$(CURL) $(LOC)/local-resource -b $(TMP)/local_user.cookies | jq .
	echo "Waiting 60 seconds for cookie to expire ..."
	for s in $$(seq 60 -1 1); do printf "  %2ds remaining...\r" $$s; sleep 1; done; echo
	echo "Call /local-resource again (should now be 401 Unauthorized):"
	$(CURL) -w "\nHTTP %{http_code}\n" -o /dev/null $(LOC)/local-resource -b $(TMP)/local_user.cookies || true
	$(CURL) $(LOC)/local-resource -b $(TMP)/local_user.cookies | jq .

.PHONY: demo-all
demo-all: up wait-all demo-centralised demo-local

.PHONY: clean
clean:
	rm -rf $(TMP)
