
import os, base64, hashlib, secrets, urllib.parse
from typing import Optional

from fastapi import FastAPI
from fastapi import Request, Body, Path, Query
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import httpx
from dotenv import load_dotenv
from fhir.resources.patient import Patient
from fhir.resources.observation import Observation
from fastapi.encoders import jsonable_encoder
from typing import Optional, Dict, Any

load_dotenv()

CLIENT_ID    = os.environ.get("EPIC_CLIENT_ID", "").strip()
AUTH_BASE    = os.environ.get("EPIC_AUTH_BASE", "").strip().rstrip("/")
FHIR_BASE    = os.environ.get("EPIC_FHIR_BASE", "").strip().rstrip("/")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:8000/callback").strip()
SCOPES       = os.environ.get("SCOPES", "openid patient/Patient.read patient/Patient.search")
PORT         = int(os.environ.get("PORT", "8000"))
SESSION_SECRET = os.environ.get("SESSION_SECRET", "please-change-me")

AUTHORIZE_URL = f"{AUTH_BASE}/oauth2/authorize" if AUTH_BASE else ""
TOKEN_URL     = f"{AUTH_BASE}/oauth2/token" if AUTH_BASE else ""

app = FastAPI(title="Epic SMART on FHIR (Patient Standalone) - FastAPI Demo")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def gen_pkce():
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge

def html_logged_menu(logged: bool) -> str:
    if not logged:
        return ""
    return (
      "<li><a href='/patient'>Patient Demographics</a></li>"
      "<li><a href='/patient/resource'>Patient Demographics - Using fhir.resources.patient</a></li>"
      "<li><a href='/patient/labs'>Patient Labs - Search</a></li>"
      "<li><a href='/patient/vitals'>Patient Vitals - Search</a></li>"
    )

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    logged_in = "access_token" in request.session
    body = f"""
    <h2>Epic SMART on FHIR - FastAPI Demo</h2>
    <p>Status: <b>{'Logged in' if logged_in else 'Not logged in'}</b></p>
    <ul>
      <li><a href="/launch">Connect Epic (Sandbox)</a></li>
      {html_logged_menu(logged_in)}
    </ul>
    <details>
      <summary>Env check</summary>
      <pre>CLIENT_ID set: {bool(CLIENT_ID)}
AUTH_BASE: {AUTH_BASE or '(unset)'}
FHIR_BASE: {FHIR_BASE or '(unset)'}
REDIRECT_URI: {REDIRECT_URI}
SCOPES: {SCOPES}</pre>
    </details>
    """
    return HTMLResponse(body)

@app.get("/launch")
async def launch(request: Request):
    if not (CLIENT_ID and AUTH_BASE and FHIR_BASE):
        return JSONResponse({"error": "missing_config", "hint": "Fill .env with EPIC_CLIENT_ID / EPIC_AUTH_BASE / EPIC_FHIR_BASE"}, status_code=400)

    verifier, challenge = gen_pkce()
    request.session["pkce_verifier"] = verifier
    state = b64url(secrets.token_bytes(24))
    request.session["oauth_state"] = state

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPES,
        "aud": FHIR_BASE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return RedirectResponse(AUTHORIZE_URL + "?" + urllib.parse.urlencode(params))

@app.get("/callback")
async def callback(request: Request, code: Optional[str] = None, state: Optional[str] = None):
    if state != request.session.get("oauth_state") or not code:
        return JSONResponse({"error": "state_or_code_invalid"}, status_code=400)

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": request.session.get("pkce_verifier"),
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(TOKEN_URL, data=data)
    if r.status_code != 200:
        return JSONResponse({"error": "token_exchange_failed", "detail": r.text}, status_code=400)

    token = r.json()
    print("EPIC TOKEN RESPONSE:", token) # print to console for demo purposes

    request.session["access_token"]  = token.get("access_token")
    request.session["refresh_token"] = token.get("refresh_token") # may be absent
    request.session["id_token"]      = token.get("id_token")
    request.session["scope"]         = token.get("scope")
    request.session['patient']       = token.get("patient")  # may be absent
    return RedirectResponse("/")

@app.get("/patient")
async def get_patient(request: Request, id: Optional[str] = None):
    """
    读取患者基本信息（Patient/{id}）。
    - 默认用 session 里的 patient_id；也可通过 query 覆盖：/patient?id=abc
    """
    access_token = request.session.get("access_token")
    if not access_token:
        return JSONResponse({"error": "not_logged_in"}, status_code=401)

    patient_id = id or request.session.get("patient")
    if not patient_id:
        # 如果没存 patient_id，也可以考虑从 id_token 的 fhirUser 解析，这里先返回提示
        return JSONResponse({"error": "no_patient_id", "hint": "missing patient in session; pass ?id=... or ensure token['patient'] was stored"}, status_code=400)

    url = f"{FHIR_BASE}/Patient/{patient_id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/fhir+json",  # 明确要 JSON
    }
    params = {"_format": "json"}             # 双保险

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(url, headers=headers, params=params)
    except httpx.HTTPError as e:
        return JSONResponse({"error": "network_error", "detail": str(e)}, status_code=502)

    print("EPIC PATIENT RESPONSE:", r.json()) # print to console for demo purposes

    # 根据返回类型决定如何呈现，便于调试错误页
    ct = r.headers.get("content-type", "").lower()
    if "json" in ct:
        return JSONResponse(r.json(), status_code=r.status_code)
    else:
        return HTMLResponse(r.text, status_code=r.status_code)

@app.get("/patient/resource")
async def get_patient_demographics(request: Request, patient_id: str = None):
    access_token = request.session.get("access_token")
    if not access_token: return JSONResponse({"error": "not_logged_in"}, status_code=401)

    pid = patient_id or request.session.get("patient") 
    if not pid: return JSONResponse({"error": "no_patient_id"}, status_code=400)

    url = f"{FHIR_BASE}/Patient/{pid}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/fhir+json",  # 明确要 JSON
    }
    params = {"_format": "json"}             # 双保险

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(url, headers=headers, params=params)
    except httpx.HTTPError as e:
        return JSONResponse({"error": "network_error", "detail": str(e)}, status_code=502)
    
    print("EPIC PATIENT RESPONSE From FHIR Resource:", r.json()) # print to console for demo purposes

    if r.status_code != 200:
        return JSONResponse({"error": "epic_error", "status": r.status_code, "detail": r.text}, status_code=r.status_code)

    # 用 fhir.resources.patient.Patient 来解析
    patient = Patient.model_validate(r.json())

    #print("Parsed Patient:", patient)  # print to console for demo purposes

    # 简单组装需要的人口学信息
    demo = {
        "id": patient.id,
        "name": patient.name[0].text if patient.name else None,
        "family": patient.name[0].family if patient.name else None,
        "given": patient.name[0].given if patient.name and patient.name[0].given else None,
        "gender": patient.gender,
        "birthDate": patient.birthDate,
    }

    print("Patient Demographics:", demo)  # print to console for demo purposes

    return JSONResponse(content=jsonable_encoder(demo))

@app.get("/patient/labs") #search for list of lab results
async def search_lab_observations(
    request: Request,
    patient_id: Optional[str] = None,
    count: int = 20
):
    access_token = request.session.get("access_token")
    if not access_token:
        return JSONResponse({"error": "not_logged_in"}, status_code=401)

    patient_id = patient_id or request.session.get("patient")
    if not patient_id:
        return JSONResponse({"error": "no_patient_id"}, status_code=400)

    url = f"{FHIR_BASE}/Observation"
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/fhir+json"}
    params = {
        "category": "laboratory",
        "_count": str(count),
        "_format": "json",
        "patient": patient_id
    }

    print("params: ", params)
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(url, headers=headers, params=params)
    except httpx.HTTPError as e:
        return JSONResponse({"error": "network_error", "detail": str(e)}, status_code=502)

       # 调试信息（控制台可见）
    print("EPIC Observation lab search - response:", r.json())

    ct = r.headers.get("content-type", "").lower()
    if "json" in ct:
        bundle = r.json()

        entries = bundle.get("entry") or []
        obs_ids = []
        obs_resources = []
        outcome_warnings = []

        for e in entries:
            res = e.get("resource") or {}
            rtype = res.get("resourceType")

            # 只收 Observation（并且有 id）
            if rtype == "Observation" and res.get("id"):
                obs_ids.append(res["id"])
                obs_resources.append(res)
                continue

            # 收集 OperationOutcome 信息（常见于 Epic：部分子类型被抑制等）
            if rtype == "OperationOutcome":
                issues = res.get("issue") or []
                for iss in issues:
                    outcome_warnings.append({
                        "severity": iss.get("severity"),
                        "code": iss.get("code"),
                        "text": (iss.get("text") or (iss.get("details") or {}).get("text")),
                        "diagnostics": iss.get("diagnostics"),
                    })

        return JSONResponse({
            "ids": obs_ids,                  # 直接可用的 Observation id 列表
            "count": len(obs_ids),
            "bundle_type": bundle.get("type"),
            "outcome_warnings": outcome_warnings,  # 例如 “某些子类型未返回”
            # 如需调试可临时返回 obs_resources；生产环境别回整包
            "bundle": bundle
        }, status_code=r.status_code)
    else:
        return HTMLResponse(r.text, status_code=r.status_code)   

@app.get("/patient/observation/{observation_id}")
async def read_observation_by_id(request: Request, observation_id: str):
    access_token = request.session.get("access_token")
    if not access_token:
        return JSONResponse({"error": "not_logged_in"}, status_code=401)
    
    patient_id = patient_id or request.session.get("patient")
    if not patient_id:
        return JSONResponse({"error": "no_patient_id"}, status_code=400)

    url = f"{FHIR_BASE}/Observation/{observation_id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/fhir+json",  # 明确要 JSON
    }
    params = {"_format": "json"}             # 双保险

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(url, headers=headers, params=params)
    except httpx.HTTPError as e:
        return JSONResponse({"error": "network_error", "detail": str(e)}, status_code=502)

    print("EPIC lab single RESPONSE:", r.json()) # print to console for demo purposes

    # 根据返回类型决定如何呈现，便于调试错误页
    ct = r.headers.get("content-type", "").lower()
    if "json" in ct:
        return JSONResponse(r.json(), status_code=r.status_code)
    else:
        return HTMLResponse(r.text, status_code=r.status_code)

@app.get("/patient/vitals") #search for list of vitals
async def search_vitals(
    request: Request,
    patient_id: Optional[str] = None,
    code: Optional[str] = None,     # LOINC，可逗号分隔多个
    date: Optional[str] = None,     # e.g. "ge2024-01-01", "le2024-12-31"
    count: int = 20,                # _count
    use_subject: bool = False       # 某些环境用 subject=Patient/{id}
):
    """
    搜索某患者的 vitals（Observation.category = vital-signs）。
    可选按 LOINC code & date 过滤。返回 FHIR Bundle。
    """
    access_token = request.session.get("access_token")
    if not access_token:
        return JSONResponse({"error": "not_logged_in"}, status_code=401)

    pid = patient_id or request.session.get("patient")
    if not pid:
        return JSONResponse({"error": "no_patient_id"}, status_code=400)

    url = f"{FHIR_BASE}/Observation"
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/fhir+json"}
    params = {
        "category": "vital-signs",
        "_count": str(count),
        "_format": "json",
    }
    # patient or subject 两种写法，视环境支持情况择一
    if use_subject:
        params["subject"] = f"Patient/{pid}"
    else:
        params["patient"] = pid

    if code:
        params["code"] = code  # 多个 LOINC 用逗号分隔
    if date:
        params["date"] = date  # geYYYY-MM-DD / leYYYY-MM-DD / lt / gt

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(url, headers=headers, params=params)
    except httpx.HTTPError as e:
        return JSONResponse({"error": "network_error", "detail": str(e)}, status_code=502)

        # 调试信息（控制台可见）
    print("EPIC Observation vitals search - response:", r.json())

    # 常见：如果环境只支持 _id search，会返回 400/403
    if r.status_code == 403:
        return JSONResponse({
            "error": "forbidden",
            "hint": "环境可能未开放 Observation 列表查询（仅支持 _id）。请在 Open Epic 开启 Observation.Search (Vitals) 变体，或改用按 ID 读取。"
        }, status_code=403)

    ct = r.headers.get("content-type", "").lower()
    return JSONResponse(r.json(), status_code=r.status_code) if "json" in ct else HTMLResponse(r.text, status_code=r.status_code)

def _to_bare_id(x: str) -> str:
    return x.rstrip("/").split("/")[-1]

def _headers(token: Optional[str] = None, content_type: Optional[str] = None) -> Dict[str, str]:
    h = {"Accept": "application/fhir+json"}
    if token: h["Authorization"] = f"Bearer {token}"
    if CLIENT_ID: h["Epic-Client-ID"] = CLIENT_ID
    if content_type: h["Content-Type"] = content_type
    return h

def _build_lab_observation(
    patient_id: str,
    loinc_code: str,
    value: float,
    unit: str,
    effective: Optional[str] = None,   # e.g. "2025-08-24T10:00:00Z" 或 "2025-08-24"
    status: str = "final"
) -> Dict[str, Any]:
    """按最小字段组一个“实验室”Observation，并用 fhir.resources 校验。"""
    body = {
        "resourceType": "Observation",
        "status": status,
        "category": [{
            "coding": [{
                "system": "http://terminology.hl7.org/CodeSystem/observation-category",
                "code": "laboratory",
                "display": "Laboratory"
            }],
            "text": "Laboratory"
        }],
        "code": {
            "coding": [{
                "system": "http://loinc.org",
                "code": loinc_code
            }]
        },
        "subject": {"reference": f"Patient/{_to_bare_id(patient_id)}"},
        "valueQuantity": {"value": value, "unit": unit}
    }
    if effective:
        # 你可以传 dateTime（含时间）或 date（仅日期）；这里直接当作 effectiveDateTime
        body["effectiveDateTime"] = effective

    # 用 fhir.resources 做强校验；再导出为纯 JSON
    obs = Observation.model_validate(body)
    return obs.model_dump(mode="json", by_alias=True, exclude_none=True)

# ---------------------------- CREATE (lab) --------------------------------------
@app.post("/labs")
async def create_lab_observation(
    request: Request,
    patient_id: str = Body(..., embed=True),
    loinc: str = Body(..., embed=True, description="LOINC code, e.g. 4548-4"),
    value: float = Body(..., embed=True),
    unit: str = Body(..., embed=True),
    effective: Optional[str] = Body(None, embed=True),
    status: str = Body("final", embed=True),
    raw: Optional[Dict[str, Any]] = Body(None, embed=True, description="可选：直接传完整 Observation 覆盖以上参数"),
):
    access_token = request.session.get("access_token")
    # 允许你直接传完整 Observation；否则用上面的最小集构造
    try:
        payload = raw if (raw and raw.get("resourceType") == "Observation") \
                 else _build_lab_observation(patient_id, loinc, value, unit, effective, status)
    except Exception as e:
        return JSONResponse({"error": "validation_error", "detail": str(e)}, status_code=422)

    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(f"{FHIR_BASE}/Observation",
                              headers=_headers(access_token, "application/fhir+json"),
                              json=payload)
    ct = r.headers.get("content-type", "").lower()
    return JSONResponse(r.json() if "json" in ct else {"raw": r.text}, status_code=r.status_code)

# ---------------------------- UPDATE (lab, PUT) ---------------------------------
@app.put("/labs/{obs_id}")
async def update_lab_observation(
    request: Request,
    obs_id: str = Path(...),
    etag: Optional[str] = Query(None, description='可选并发控制：If-Match, 如 W/"3"'),
    body: Dict[str, Any] = Body(..., description="完整 Observation JSON；会强制 resourceType/Id 一致"),
):
    token = request.session.get("access_token")
    # 强制一致性
    body = dict(body)
    body["resourceType"] = "Observation"
    body["id"] = obs_id
    # 也强制 category 包含 laboratory（如果你希望硬约束）
    if not any(
        c.get("code") == "laboratory"
        for cat in (body.get("category") or [])
        for c in (cat.get("coding") or [])
    ):
        # 自动补上 laboratory 分类
        body.setdefault("category", []).append({
            "coding": [{
                "system": "http://terminology.hl7.org/CodeSystem/observation-category",
                "code": "laboratory",
                "display": "Laboratory"
            }],
            "text": "Laboratory"
        })

    # 校验
    try:
        validated = Observation.model_validate(body).model_dump(mode="json", by_alias=True, exclude_none=True)
    except Exception as e:
        return JSONResponse({"error": "validation_error", "detail": str(e)}, status_code=422)

    if not FHIR_BASE:
        return JSONResponse({"validated": validated, "note": "No FHIR_BASE; not forwarded."})

    headers = _headers(token, "application/fhir+json")
    if etag:
        headers["If-Match"] = etag
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.put(f"{FHIR_BASE}/Observation/{obs_id}", headers=headers, json=validated)
    ct = r.headers.get("content-type", "").lower()
    return JSONResponse(r.json() if "json" in ct else {"raw": r.text}, status_code=r.status_code)

# ---------------------------- DELETE (lab) --------------------------------------
@app.delete("/labs/{obs_id}")
async def delete_lab_observation(request: Request, obs_id: str):
    token = request.session.get("access_token")
    if not FHIR_BASE:
        return JSONResponse({"note": "No FHIR_BASE; simulated delete.", "id": obs_id})

    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.delete(f"{FHIR_BASE}/Observation/{obs_id}", headers=_headers(token))
    ct = r.headers.get("content-type", "").lower()
    return JSONResponse(r.json() if "json" in ct else {"status": r.status_code, "raw": r.text},
                        status_code=r.status_code)


