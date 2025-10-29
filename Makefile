# Makefile — Demo flows for SDA4 Zero Trust assignment
# Usage:
#   make help
#   make up
#   make demo-all

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
	echo "  up                 Build & start all services (waits for health)"
	echo "  down               Stop & remove services"
	echo "  logs               Tail logs"
	echo "  deps               Check local CLI deps (curl, jq)"
	echo "  login-analyst      Get IdP token for analyst (registered device)"
	echo "  login-admin        Get IdP token for admin (registered device)"
	echo "  login-analyst-rogue    Get IdP token for analyst (unknown device)"
	echo "  login-analyst-nodevice Get IdP token for analyst (no device)"
	echo "  call-resource-allow    /resource allow (analyst)"
	echo "  call-export-challenge  /export challenge (analyst)"
	echo "  call-export-admin      /export allow (admin)"
	echo "  call-resource-deny-unknown-device  deny"
	echo "  call-resource-deny-missing-device  deny"
	echo "  offhours-note        Explain how to see off-hours deny"
	echo "  local-login-user     Local Service cookie session (user)"
	echo "  local-login-admin    Local Service cookie session (admin)"
	echo "  local-user-resource  /local-resource with user cookie"
	echo "  local-user-admin     /local-admin with user cookie (expect 403)"
	echo "  local-admin-admin    /local-admin with admin cookie (expect 200)"
	echo "  demo-all           Run the full happy-path demo set"
	echo "  clean              Remove .tmp artifacts"

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

# --- Wait for services to be ready -------------------------------------------

.PHONY: wait-idp wait-resource wait-local wait-all
wait-idp:
	echo "Waiting for IdP ..."
	for i in {1..40}; do \
	  if $(CURL) $(IDP)/health >/dev/null; then echo "IdP ready"; exit 0; fi; \
	  sleep 0.5; \
	done; \
	echo "IdP not ready"; exit 1

wait-resource:
	echo "Waiting for Resource API ..."
	for i in {1..40}; do \
	  if $(CURL) $(RES)/health >/dev/null; then echo "Resource API ready"; exit 0; fi; \
	  sleep 0.5; \
	done; \
	echo "Resource API not ready"; exit 1

wait-local:
	echo "Waiting for Local Service ..."
	for i in {1..40}; do \
	  if $(CURL) $(LOC)/health >/dev/null; then echo "Local Service ready"; exit 0; fi; \
	  sleep 0.5; \
	done; \
	echo "Local Service not ready"; exit 1

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
	      printf "%s" "$$TOKEN" > "$$OUT"; echo "Saved token → $$OUT"; exit 0; \
	    fi; \
	  fi; \
	  echo "Login attempt $$i failed (HTTP $$CODE): $$BODY"; sleep 1; \
	done; \
	echo "Login failed after 5 attempts"; exit 1
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
	echo "Expect DENY (device not trusted)"
	# show HTTP status cleanly (GET; no -I which triggers 405)
	$(CURL) -w "\nHTTP %{http_code}\n" -o /dev/null \
	  $(RES)/resource $(call _bearer,$(TMP)/analyst-rogue.token)
	# then show JSON body
	$(CURL) $(RES)/resource $(call _bearer,$(TMP)/analyst-rogue.token) | jq .

.PHONY: call-resource-deny-missing-device
call-resource-deny-missing-device: login-analyst-nodevice wait-resource
	echo "Expect DENY (device not trusted / missing)"
	$(CURL) -w "\nHTTP %{http_code}\n" -o /dev/null \
	  $(RES)/resource $(call _bearer,$(TMP)/analyst-nodevice.token)
	$(CURL) $(RES)/resource $(call _bearer,$(TMP)/analyst-nodevice.token) | jq .

.PHONY: offhours-note
offhours-note:
	echo "To see off-hours denial, run after local business hours (07:00–19:00 Europe/Zurich)."
	echo "Alternatively, temporarily adjust BUSINESS_HOURS_* in resource_api/.env and restart the service."

# --- Local Service cookie flow (decentralised) --------------------------------

.PHONY: local-login-user
local-login-user: deps wait-local
	mkdir -p $(TMP)
	$(CURL) -X POST $(LOC)/local-login \
	  -H 'Content-Type: application/json' \
	  -d '{"username":"localuser","password":"local"}' \
	  -c $(TMP)/local_user.cookies | jq .
	echo "Cookie jar saved → $(TMP)/local_user.cookies"

.PHONY: local-login-admin
local-login-admin: deps wait-local
	mkdir -p $(TMP)
	$(CURL) -X POST $(LOC)/local-login \
	  -H 'Content-Type: application/json' \
	  -d '{"username":"localadmin","password":"admin"}' \
	  -c $(TMP)/local_admin.cookies | jq .
	echo "Cookie jar saved → $(TMP)/local_admin.cookies"

.PHONY: local-user-resource
local-user-resource: local-login-user wait-local
	$(CURL) $(LOC)/local-resource -b $(TMP)/local_user.cookies | jq .

.PHONY: local-user-admin
local-user-admin: local-login-user wait-local
	echo "Expect 403 (user is not admin) — show HTTP code then JSON body"
	$(CURL) -w "\nHTTP %{http_code}\n" -o /dev/null \
	  $(LOC)/local-admin -b $(TMP)/local_user.cookies
	$(CURL) $(LOC)/local-admin -b $(TMP)/local_user.cookies | jq .

.PHONY: local-admin-admin
local-admin-admin: local-login-admin wait-local
	echo "Expect 200 (admin)"
	$(CURL) $(LOC)/local-admin -b $(TMP)/local_admin.cookies | jq .

# --- Rollups ------------------------------------------------------------------

.PHONY: demo-centralised
demo-centralised: call-resource-allow call-export-challenge call-export-admin call-resource-deny-unknown-device call-resource-deny-missing-device

.PHONY: demo-local
demo-local: local-user-resource local-user-admin local-admin-admin

.PHONY: demo-all
demo-all: up wait-all demo-centralised demo-local

.PHONY: clean
clean:
	rm -rf $(TMP)
