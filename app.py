#!/usr/bin/env python3
import json
import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

import requests
from flask import Flask, request, redirect, url_for, render_template, abort

APP_STAGE = 309
ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "stage309_history.sqlite3"
POLICY_DIR = ROOT / "policies"
DEFAULT_MANIFEST_PATH = ROOT / "samples" / "manifest.json"

STAGE289_VERIFY_URL = "http://127.0.0.1:2890/api/verify"

app = Flask(__name__)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def get_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS verification_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            input_url TEXT,
            manifest_sha256 TEXT,
            policy_id TEXT,
            policy_version TEXT,
            policy_sha256 TEXT,
            decision TEXT,
            action TEXT,
            trust_score REAL,
            reason TEXT,
            upstream_source TEXT,
            upstream_status TEXT,
            result_json TEXT
        )
        """)
        conn.commit()


def list_policies():
    items = []
    for p in sorted(POLICY_DIR.glob("policy_v*.json")):
        text = p.read_text(encoding="utf-8")
        data = json.loads(text)
        items.append({
            "data": data,
            "policy_id": data["policy_id"],
            "policy_version": data["policy_version"],
            "sha256": sha256_text(text)
        })
    return items


def evaluate_local(manifest, policy_item):
    rules = policy_item["data"]["rules"]
    claims = manifest["claims"]
    identity = manifest["identity_evidence"]

    failures = []

    if rules["require_gpg_verified_identity"] and not identity["gpg_verified"]:
        failures.append("GPG missing")
    if rules["require_sigstore_verified_identity"] and not identity["sigstore_verified"]:
        failures.append("Sigstore missing")

    decision = "accept" if not failures else "reject"

    return {
        "decision": decision,
        "reason": "OK" if not failures else "; ".join(failures),
        "trust_score": 1.0 if decision == "accept" else 0.0
    }


def save_result(data):
    with get_db() as conn:
        cur = conn.execute("""
        INSERT INTO verification_history VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, data)
        conn.commit()
        return cur.lastrowid


@app.route("/")
def home():
    return redirect("/verify")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    policies = list_policies()

    if request.method == "GET":
        return render_template("verify.html",
            policies=policies,
            manifest=DEFAULT_MANIFEST_PATH.read_text(),
            url="https://example.com"
        )

    manifest = json.loads(request.form["manifest"])
    policy_id = request.form["policy"]

    policy = [p for p in policies if p["policy_id"] == policy_id][0]

    result = evaluate_local(manifest, policy)

    row_id = save_result((
        now_iso(),
        request.form["url"],
        sha256_text(json.dumps(manifest)),
        policy["policy_id"],
        policy["policy_version"],
        policy["sha256"],
        result["decision"],
        "allow" if result["decision"] == "accept" else "block",
        result["trust_score"],
        result["reason"],
        "local",
        "ok",
        json.dumps(result)
    ))

    return redirect(f"/result/{row_id}")


@app.route("/history")
def history():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM verification_history ORDER BY id DESC").fetchall()
    return render_template("history.html", rows=rows)


@app.route("/result/<int:id>")
def result(id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM verification_history WHERE id=?", (id,)).fetchone()
    return render_template("result.html", row=row)


if __name__ == "__main__":
    init_db()
    app.run(port=3090, debug=True)
