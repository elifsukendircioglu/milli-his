import json
import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from kimlik_dogrulama import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
)
from database import get_db, init_db
from tarama import run_nmap
from analiz import analyze
from rapor import create_pdf

app = FastAPI(title="Milli HIS - Yerli Zafiyet Tarama Sistemi")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()


class RegisterRequest(BaseModel):
    username: str
    password: str


class ScanRequest(BaseModel):
    target: str


@app.post("/register")
def register(req: RegisterRequest):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (req.username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Bu kullanici adi zaten alinmis.")
    hashed = hash_password(req.password)
    cursor.execute(
        "INSERT INTO users (username, hashed_password) VALUES (?, ?)",
        (req.username, hashed),
    )
    conn.commit()
    conn.close()
    return {"message": "Kullanici basariyla olusturuldu."}


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND is_active = 1",
        (form_data.username,),
    )
    user = cursor.fetchone()
    conn.close()

    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kullanici adi veya sifre hatali.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/scan")
def scan(req: ScanRequest, current_user: dict = Depends(get_current_user)):
    nmap_result = run_nmap(req.target)
    if nmap_result.get("error"):
        raise HTTPException(status_code=500, detail=nmap_result["error"])

    hosts_raw = nmap_result.get("hosts", {})

    if not hosts_raw:
        return {
            "scan_id": None,
            "target": req.target,
            "risk_score": 0.0,
            "hosts": [],
            "ports": [],
        }

    analyzed = analyze(hosts_raw)
    risk_score = analyzed.get("risk_score", 0.0)

    # hosts dict → list çevir (frontend için)
    hosts_list = list(analyzed["hosts"].values())

    result_json = json.dumps(
        {"target": req.target, "hosts": hosts_list},
        ensure_ascii=False
    )

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (target, result_json, risk_score, status, scanned_by) VALUES (?, ?, ?, 'done', ?)",
        (req.target, result_json, risk_score, current_user["id"]),
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {
        "scan_id": scan_id,
        "target": req.target,
        "risk_score": risk_score,
        "hosts": hosts_list,
        # Tek IP taraması için geriye dönük uyumluluk
        "ports": hosts_list[0]["ports"] if len(hosts_list) == 1 else [],
    }


@app.get("/scans")
def get_scans(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, target, risk_score, status, scanned_at FROM scans WHERE scanned_by = ? ORDER BY scanned_at DESC",
        (current_user["id"],),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/report/{scan_id}")
def get_report(scan_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM scans WHERE id = ? AND scanned_by = ?",
        (scan_id, current_user["id"]),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Tarama bulunamadi.")

    scan_data = dict(row)
    scan_data["result"] = json.loads(scan_data["result_json"])

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(BASE_DIR, "data", "reports")
    os.makedirs(reports_dir, exist_ok=True)
    pdf_path = os.path.join(reports_dir, f"rapor_{scan_id}.pdf")

    create_pdf(scan_data, pdf_path)

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"milli-his-rapor-{scan_id}.pdf",
    )