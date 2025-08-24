
# Epic SMART on FHIR (Patient Standalone) — FastAPI Demo

A minimal local demo that performs SMART on FHIR patient-facing standalone login with PKCE, then calls Epic FHIR endpoints (/metadata, /Patient, /Observation).

## 1) Setup

```bash
python -m venv venv
# macOS/Linux:
source venv/bin/activate
# Windows:
# venv\Scripts\activate

pip install -r requirements.txt
cp .env.example .env
# edit .env and fill EPIC_CLIENT_ID / EPIC_AUTH_BASE / EPIC_FHIR_BASE / REDIRECT_URI / SESSION_SECRET
```

Notes
- REDIRECT_URI must exactly match the Redirect URI you registered in Epic (e.g. http://localhost:8000/callback).
- EPIC_FHIR_BASE should be the R4 base, and the authorize request uses aud=EPIC_FHIR_BASE.
- Scopes to start with: openid profile fhirUser patient/*.read patient/*.search offline_access.

## 2) Run

```bash
uvicorn main:app --reload --port 8000
# open http://localhost:8000
# click "Connect Epic (Sandbox)" to start OAuth; login with Epic Sandbox MyChart test account
```

## 3) Routes

- GET /             landing page + status
- GET /launch       start OAuth (PKCE)
- GET /callback     OAuth redirect target (code exchange)
- GET /metadata     FHIR CapabilityStatement
- GET /me           current Patient
- GET /observations first 10 Observations (by Patient if possible)
- GET /refresh      refresh access token (requires offline_access)
- GET /logout       clear session

## 4) Common issues

- redirect_uri_mismatch — ensure .env REDIRECT_URI exactly equals the value in Epic app settings.
- 403 on list queries — add patient/*.search (many servers require .search for bundle queries).
- aud invalid — ensure authorize request uses aud=EPIC_FHIR_BASE.
- No refresh_token — include offline_access in scopes.
