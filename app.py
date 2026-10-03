from __future__ import annotations

import os
import re
import secrets
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Thread
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Tokens live only in process memory; the browser receives an opaque session id.
SESSIONS: dict[str, dict] = {}
SESSION_LOCK = Lock()
JOBS: dict[str, dict] = {}
JOB_LOCK = Lock()
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
CF_BASE = "https://api.cloudflare.com/client/v4"


def get_session(create: bool = False):
    sid = request.cookies.get("cf_bulk_sid")
    if sid and sid in SESSIONS:
        return sid, SESSIONS[sid]
    if not create:
        return None, None
    sid = secrets.token_urlsafe(32)
    with SESSION_LOCK:
        SESSIONS[sid] = {"token": None, "account_id": None, "zones": [], "created": datetime.now(timezone.utc).isoformat()}
    return sid, SESSIONS[sid]


def reply(payload, sid=None, status=200):
    response = jsonify(payload)
    if sid:
        response.set_cookie("cf_bulk_sid", sid, httponly=True, samesite="Lax", secure=False, max_age=8 * 3600)
    return response, status


def cf_request(session, method, path, **kwargs):
    if not session.get("token"):
        raise ValueError("لم تتم المصادقة بعد")
    headers = kwargs.pop("headers", {})
    headers.update({"Authorization": f"Bearer {session['token']}", "Content-Type": "application/json"})
    r = requests.request(method, CF_BASE + path, headers=headers, timeout=25, **kwargs)
    try:
        data = r.json()
    except ValueError:
        raise RuntimeError(f"Cloudflare أعاد استجابة غير مفهومة ({r.status_code})")
    if not r.ok or not data.get("success", False):
        errors = "; ".join(str(e.get("message", e)) for e in data.get("errors", [])) or f"HTTP {r.status_code}"
        raise RuntimeError(errors)
    return data


def clean_domains(raw: str):
    out, seen = [], set()
    for line in (raw or "").splitlines():
        value = line.strip().lower()
        if not value or value.startswith("#"):
            continue
        if "," in value:
            value = value.split(",")[0].strip()
        value = re.sub(r"^https?://", "", value).split("/", 1)[0].rstrip(".")
        if DOMAIN_RE.match(value) and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def zone_map(session):
    return {z["name"].lower(): z for z in session.get("zones", [])}


def fetch_zones(session):
    zones = []
    page = 1
    while True:
        query = {"page": page, "per_page": 50, "status": "active"}
        if session.get("account_id"):
            query["account.id"] = session["account_id"]
        data = cf_request(session, "GET", "/zones", params=query)
        zones.extend(data.get("result", []))
        info = data.get("result_info", {})
        if page >= info.get("total_pages", page):
            break
        page += 1
    session["zones"] = [{"id": z["id"], "name": z["name"], "status": z.get("status")} for z in zones]
    session["last_zones_refresh"] = datetime.now(timezone.utc).isoformat()
    return session["zones"]


@app.get("/")
def index():
    return render_template("index.html")


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": f"API endpoint not found: {request.path}"}), 404
    return error


@app.errorhandler(500)
def internal_error(error):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "حدث خطأ داخلي في الخادم أثناء تنفيذ الطلب"}), 500
    return error


@app.get("/api/status")
def status():
    sid, session = get_session()
    return jsonify({"connected": bool(session and session.get("token")), "zones": len(session.get("zones", [])) if session else 0, "zone_list": session.get("zones", []) if session else [], "last_refresh": session.get("last_zones_refresh") if session else None})


@app.post("/api/refresh-zones")
def refresh_zones():
    sid, session = get_session()
    if not session or not session.get("token"):
        return jsonify({"ok": False, "error": "انتهت الجلسة؛ سجّل الدخول مرة أخرى"}), 401
    try:
        zones = fetch_zones(session)
        return jsonify({"ok": True, "zones": zones, "message": f"تم تحديث القائمة: {len(zones)} دومين"})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502


@app.post("/api/connect")
def connect():
    sid, session = get_session(create=True)
    body = request.get_json(silent=True) or {}
    token = (body.get("token") or "").strip()
    account_id = (body.get("account_id") or "").strip() or None
    if not token:
        return reply({"ok": False, "error": "أدخل API Token أولًا"}, sid, 400)
    session["token"] = token
    session["account_id"] = account_id
    try:
        data = cf_request(session, "GET", "/user/tokens/verify")
        token_status = data.get("result", {}).get("status")
        if token_status != "active":
            raise RuntimeError(f"حالة الـ API Token هي: {token_status or 'غير معروفة'}")
        try:
            zones = fetch_zones(session)
        except Exception as exc:
            raise RuntimeError(f"تم قبول التوكن، لكن فشل جلب الدومينات. تأكد من Zone:Read وAccount ID. التفاصيل: {exc}") from exc
        return reply({"ok": True, "zones": zones, "message": f"تم الاتصال وجلب {len(zones)} دومين"}, sid)
    except Exception as exc:
        session["token"] = None
        return reply({"ok": False, "error": str(exc)}, sid, 401)


@app.post("/api/disconnect")
def disconnect():
    sid, session = get_session()
    if session:
        session.clear()
    response = jsonify({"ok": True})
    response.delete_cookie("cf_bulk_sid")
    return response


@app.post("/api/parse-domains")
def parse_domains():
    body = request.get_json(silent=True) or {}
    requested = clean_domains(body.get("text", ""))
    sid, session = get_session()
    if not session:
        return jsonify({"ok": False, "error": "اتصل بـ Cloudflare أولًا"}), 401
    available = zone_map(session)
    existing = [d for d in requested if d in available]
    missing = [d for d in requested if d not in available]
    return jsonify({"ok": True, "requested": requested, "existing": existing, "missing": missing})


def normalize_ops(body):
    ops = []
    for raw in body.get("records", [])[:100]:
        typ = str(raw.get("type", "")).upper().strip()
        name = str(raw.get("name", "")).strip()
        content = str(raw.get("content", "")).strip()
        if typ not in {"A", "AAAA", "CNAME", "TXT", "MX", "NS", "CAA", "SRV"} or not name or not content:
            continue
        operation = str(raw.get("operation", "upsert")).lower().strip()
        if operation not in {"upsert", "delete"}:
            operation = "upsert"
        record = {"operation": operation, "type": typ, "name": name, "content": content, "ttl": int(raw.get("ttl") or 1)}
        if typ in {"A", "AAAA", "CNAME"}:
            record["proxied"] = bool(raw.get("proxied", False))
        if typ in {"MX", "SRV"} and raw.get("data"):
            record["data"] = raw["data"]
        ops.append(record)
    return ops


def find_record(session, zone_id, record):
    params = {"type": record["type"], "name": record["name"], "per_page": 100}
    data = cf_request(session, "GET", f"/zones/{zone_id}/dns_records", params=params)
    for item in data.get("result", []):
        if item.get("content") == record["content"]:
            return item
    return None


def effective_record(record, zone_name):
    """Cloudflare expects the zone FQDN, not the UI shorthand '@'."""
    effective = dict(record)
    effective.pop("operation", None)
    if effective.get("name") == "@":
        effective["name"] = zone_name
    elif effective.get("name") == "*":
        effective["name"] = f"*.{zone_name}"
    if effective.get("content") == "@" and effective.get("type") in {"CNAME", "MX", "NS"}:
        effective["content"] = zone_name
    return effective


def apply_one_zone(job_id, session, zone, domain, records):
    zone_state = next(z for z in JOBS[job_id]["zones"] if z["domain"] == domain)
    failed = False
    for record in records:
        try:
            effective = effective_record(record, zone["name"])
            existing = find_record(session, zone["id"], effective)
            if record.get("operation") == "delete":
                if existing:
                    cf_request(session, "DELETE", f"/zones/{zone['id']}/dns_records/{existing['id']}")
                    action = "deleted"
                else:
                    action = "skipped"
            elif existing:
                data = cf_request(session, "PUT", f"/zones/{zone['id']}/dns_records/{existing['id']}", json=effective)
                action = "updated"
            else:
                data = cf_request(session, "POST", f"/zones/{zone['id']}/dns_records", json=effective)
                action = "created"
            result = {"domain": domain, "status": "success", "action": action, "type": record["type"], "name": record["name"], "record_id": existing.get("id") if existing else None}
        except Exception as exc:
            failed = True
            result = {"domain": domain, "status": "failed", "type": record["type"], "name": record["name"], "message": str(exc)}
        with JOB_LOCK:
            JOBS[job_id]["results"].append(result)
            zone_state["completed"] += 1
    with JOB_LOCK:
        zone_state["status"] = "partial" if failed else "success"
        zone_state["message"] = "اكتمل مع وجود أخطاء" if failed else "تم بنجاح"


def run_apply_job(job_id, session, domains, records, max_workers=8):
    """Run independent zones concurrently while preserving per-zone progress."""
    available = zone_map(session)
    states = [{"domain": domain, "status": "queued", "completed": 0, "total": len(records), "message": "في الانتظار"} for domain in domains]
    with JOB_LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["zones"] = states
    workers = min(max(1, max_workers), 8, max(1, len(domains)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cf-zone") as pool:
        futures = []
        for domain in domains:
            zone = available.get(domain)
            if not zone:
                state = next(z for z in states if z["domain"] == domain)
                state.update({"status": "failed", "message": "الدومين غير موجود"})
                continue
            state = next(z for z in states if z["domain"] == domain)
            state["status"] = "running"
            futures.append(pool.submit(apply_one_zone, job_id, session, zone, domain, records))
        for future in as_completed(futures):
            future.result()
    with JOB_LOCK:
        job = JOBS[job_id]
        job["status"] = "complete"
        job["success_count"] = sum(r["status"] == "success" for r in job["results"])
        job["failed_count"] = sum(r["status"] == "failed" for r in job["results"])


def fetch_all_dns_records(session, zone_id):
    records = []
    page = 1
    while True:
        data = cf_request(session, "GET", f"/zones/{zone_id}/dns_records", params={"page": page, "per_page": 100})
        records.extend(data.get("result", []))
        info = data.get("result_info", {})
        if page >= info.get("total_pages", page):
            return records
        page += 1


def delete_all_one_zone(job_id, session, zone, domain):
    state = next(z for z in JOBS[job_id]["zones"] if z["domain"] == domain)
    try:
        dns_records = fetch_all_dns_records(session, zone["id"])
        with JOB_LOCK:
            state["total"] = len(dns_records)
            state["message"] = "جارِ حذف السجلات"
        for record in dns_records:
            try:
                cf_request(session, "DELETE", f"/zones/{zone['id']}/dns_records/{record['id']}")
                result = {"domain": domain, "status": "success", "action": "deleted", "type": record.get("type"), "name": record.get("name")}
            except Exception as exc:
                result = {"domain": domain, "status": "failed", "action": "delete", "type": record.get("type"), "name": record.get("name"), "message": str(exc)}
            with JOB_LOCK:
                JOBS[job_id]["results"].append(result)
                state["completed"] += 1
                if result["status"] == "failed":
                    state["status"] = "partial"
        with JOB_LOCK:
            if state["status"] != "partial":
                state["status"] = "success"
            state["message"] = "لا توجد سجلات" if not dns_records else ("اكتمل مع وجود أخطاء" if state["status"] == "partial" else "تم حذف كل السجلات")
    except Exception as exc:
        with JOB_LOCK:
            state.update({"status": "failed", "message": str(exc)})


def run_delete_all_job(job_id, session, domains, max_workers=8):
    available = zone_map(session)
    states = [{"domain": domain, "status": "queued", "completed": 0, "total": 0, "message": "في الانتظار"} for domain in domains]
    with JOB_LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["zones"] = states
    workers = min(max(1, max_workers), 8, max(1, len(domains)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cf-delete") as pool:
        futures = []
        for domain in domains:
            zone = available.get(domain)
            state = next(z for z in states if z["domain"] == domain)
            if not zone:
                state.update({"status": "failed", "message": "الدومين غير موجود"})
                continue
            state["status"] = "running"
            futures.append(pool.submit(delete_all_one_zone, job_id, session, zone, domain))
        for future in as_completed(futures):
            future.result()
    with JOB_LOCK:
        job = JOBS[job_id]
        job["status"] = "complete"
        job["success_count"] = sum(r["status"] == "success" for r in job["results"])
        job["failed_count"] = sum(r["status"] == "failed" for r in job["results"])


@app.post("/api/preview")
def preview():
    sid, session = get_session()
    if not session or not session.get("token"):
        return jsonify({"ok": False, "error": "اتصل بـ Cloudflare أولًا"}), 401
    body = request.get_json(silent=True) or {}
    domains = clean_domains("\n".join(body.get("domains", [])))
    records = normalize_ops(body)
    available = zone_map(session)
    items = []
    for domain in domains:
        if domain not in available:
            items.append({"domain": domain, "status": "missing", "message": "غير موجود في الحساب"})
            continue
        for record in records:
            items.append({"domain": domain, "status": "ready", "action": record.get("operation", "upsert"), "record": record})
    return jsonify({"ok": True, "items": items, "domains": len(domains), "records": len(records)})


@app.post("/api/apply")
def apply_changes():
    sid, session = get_session()
    if not session or not session.get("token"):
        return jsonify({"ok": False, "error": "اتصل بـ Cloudflare أولًا"}), 401
    body = request.get_json(silent=True) or {}
    domains = clean_domains("\n".join(body.get("domains", [])))
    records = normalize_ops(body)
    if not body.get("confirm"):
        return jsonify({"ok": False, "error": "التنفيذ يحتاج تأكيدًا صريحًا"}), 400
    available = zone_map(session)
    results = []
    for domain in domains:
        zone = available.get(domain)
        if not zone:
            results.append({"domain": domain, "status": "failed", "message": "الدومين غير موجود"})
            continue
        for record in records:
            try:
                effective = effective_record(record, zone["name"])
                existing = find_record(session, zone["id"], effective)
                if record.get("operation") == "delete":
                    if existing:
                        cf_request(session, "DELETE", f"/zones/{zone['id']}/dns_records/{existing['id']}")
                        action = "deleted"
                    else:
                        action = "skipped"
                elif existing:
                    record_id = existing["id"]
                    data = cf_request(session, "PUT", f"/zones/{zone['id']}/dns_records/{record_id}", json=effective)
                    action = "updated"
                else:
                    data = cf_request(session, "POST", f"/zones/{zone['id']}/dns_records", json=effective)
                    action = "created"
                results.append({"domain": domain, "status": "success", "action": action, "type": record["type"], "name": record["name"], "record_id": existing.get("id") if existing else None})
            except Exception as exc:
                results.append({"domain": domain, "status": "failed", "type": record["type"], "name": record["name"], "message": str(exc)})
    return jsonify({"ok": True, "results": results, "success_count": sum(r["status"] == "success" for r in results), "failed_count": sum(r["status"] == "failed" for r in results)})


@app.post("/api/apply-start")
def apply_start():
    sid, session = get_session()
    if not session or not session.get("token"):
        return jsonify({"ok": False, "error": "اتصل بـ Cloudflare أولًا"}), 401
    body = request.get_json(silent=True) or {}
    domains = clean_domains("\n".join(body.get("domains", [])))
    records = normalize_ops(body)
    if not body.get("confirm"):
        return jsonify({"ok": False, "error": "التنفيذ يحتاج تأكيدًا صريحًا"}), 400
    if not domains or not records:
        return jsonify({"ok": False, "error": "اختر دومينًا وأضف سجلًا أولًا"}), 400
    job_id = secrets.token_urlsafe(18)
    with JOB_LOCK:
        JOBS[job_id] = {"status": "queued", "zones": [], "results": [], "success_count": 0, "failed_count": 0, "created": datetime.now(timezone.utc).isoformat()}
    Thread(target=run_apply_job, args=(job_id, session, domains, records), daemon=True).start()
    return jsonify({"ok": True, "job_id": job_id, "total_zones": len(domains), "total_records": len(records)})


@app.post("/api/delete-all-start")
def delete_all_start():
    sid, session = get_session()
    if not session or not session.get("token"):
        return jsonify({"ok": False, "error": "اتصل بـ Cloudflare أولًا"}), 401
    body = request.get_json(silent=True) or {}
    domains = clean_domains("\n".join(body.get("domains", [])))
    if not body.get("confirm"):
        return jsonify({"ok": False, "error": "حذف كل السجلات يحتاج تأكيدًا صريحًا"}), 400
    if not domains:
        return jsonify({"ok": False, "error": "حدد دومينًا واحدًا على الأقل"}), 400
    job_id = secrets.token_urlsafe(18)
    with JOB_LOCK:
        JOBS[job_id] = {"status": "queued", "mode": "delete_all", "zones": [], "results": [], "success_count": 0, "failed_count": 0, "created": datetime.now(timezone.utc).isoformat()}
    Thread(target=run_delete_all_job, args=(job_id, session, domains), daemon=True).start()
    return jsonify({"ok": True, "job_id": job_id, "total_zones": len(domains)})


@app.get("/api/apply-status/<job_id>")
def apply_status(job_id):
    with JOB_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"ok": False, "error": "عملية التنفيذ غير موجودة"}), 404
        return jsonify({"ok": True, **job})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
