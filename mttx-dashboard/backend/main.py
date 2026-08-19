import os
import re
import json
import random
import sqlite3
import logging
import uvicorn
import statistics
import threading
import time
import secrets
import tempfile
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Depends, HTTPException, APIRouter, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel, field_validator
from typing import List, Optional

VERSION = "1.0.0"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    from secops import SecOpsClient
    SECOPS_SDK_AVAILABLE = True
except ImportError:
    SECOPS_SDK_AVAILABLE = False

# The service-account key (uploaded from Settings) is stored next to the DB — see _SA_PATH
# below, defined after the DB path is resolved so it lands in a writable directory.
def _sa_path_or_none():
    return _SA_PATH if os.path.exists(_SA_PATH) else None

def _secops_client() -> "SecOpsClient":
    return SecOpsClient(service_account_path=_sa_path_or_none())

# Standalone MTTX Dashboard — its own DB (fully self-contained, shares nothing).
# The DB must be *writable*. If the default location (or an existing file) is read-only —
# e.g. the folder was copied read-only, or a previous run under sudo left a root-owned file —
# fall back to a guaranteed-writable location so setup (password, tenants, …) always works.
def _sqlite_writable(path: str) -> bool:
    try:
        d = os.path.dirname(path) or "."
        os.makedirs(d, exist_ok=True)
        con = sqlite3.connect(path, timeout=2)
        con.execute("CREATE TABLE IF NOT EXISTS _mttx_wtest (x INTEGER)")
        con.execute("DROP TABLE IF EXISTS _mttx_wtest")
        con.commit(); con.close()
        return True
    except Exception:
        return False

def _resolve_db_path() -> str:
    candidates = []
    if os.environ.get("MTTX_DB"):
        candidates.append(os.path.abspath(os.path.expanduser(os.environ["MTTX_DB"])))
    candidates.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "mttx_dashboard.db")))
    candidates.append(os.path.join(os.path.expanduser("~"), ".mttx-dashboard", "mttx_dashboard.db"))
    candidates.append(os.path.join(tempfile.gettempdir(), "mttx_dashboard.db"))
    for p in candidates:
        if _sqlite_writable(p):
            return p
    return candidates[-1]

_DB_PATH = _resolve_db_path()
_DEFAULT_DB = os.path.abspath(os.path.join(os.path.dirname(__file__), "mttx_dashboard.db"))
if _DB_PATH != _DEFAULT_DB:
    logging.warning("Default DB not writable; using %s instead (set MTTX_DB to override).", _DB_PATH)

# Store the uploaded service-account key next to the DB (guaranteed-writable directory).
_SA_PATH = os.path.join(os.path.dirname(_DB_PATH), "sa.json")
if os.path.exists(_SA_PATH):
    os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", _SA_PATH)

DATABASE_URL = f"sqlite:///{_DB_PATH}"
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    guid = Column(String, unique=True, index=True, nullable=False)
    region = Column(String, nullable=False)
    gcp_project_id = Column(String, nullable=False)
    base_url = Column(String, nullable=True)




class CaseExclusion(Base):
    """Configurable case filter — cases whose case_display / rule_name / alert_names
    contain this 'keyword' are dropped from MTTX. Not hard-coded in the source; stored
    in the DB and managed from the Settings screen."""
    __tablename__ = "case_exclusions"
    id         = Column(Integer, primary_key=True, index=True)
    keyword    = Column(String, nullable=False)
    note       = Column(String, nullable=True)
    created_at = Column(String, default=lambda: datetime.utcnow().isoformat())


class AppSetting(Base):
    """Generic key/value store for app-level configuration (e.g. branding logo).
    Nothing organization-specific is baked into the source — set it from Settings."""
    __tablename__ = "app_settings"
    key   = Column(String, primary_key=True, index=True)
    value = Column(String, nullable=True)


Base.metadata.create_all(bind=engine)


def _get_setting(key: str, default: str = "") -> str:
    try:
        _db = SessionLocal()
        row = _db.query(AppSetting).filter(AppSetting.key == key).first()
        _db.close()
        return row.value if row and row.value is not None else default
    except Exception:
        return default

# Ships EMPTY — no organization-specific filters baked in. Add your own via Settings.
_DEFAULT_EXCLUSIONS = []

def _load_exclusion_keywords():
    """Active filter keywords, read from the DB (single source of truth)."""
    try:
        _db = SessionLocal()
        _rows = _db.query(CaseExclusion).all()
        _db.close()
        return [r.keyword for r in _rows if r.keyword]
    except Exception:
        return []


class TenantBase(BaseModel):
    name: str
    guid: str
    region: str
    gcp_project_id: str
    base_url: Optional[str] = None

    @field_validator('base_url')
    def clean_url(cls, v):
        if v:
            return v.strip().rstrip('/')
        return v

class TenantCreate(TenantBase): pass
class TenantUpdate(TenantBase): pass

class TenantResponse(TenantBase):
    id: int
    class Config: from_attributes = True


class TestConnectionResponse(BaseModel):
    status: str
    message: str

class VersionResponse(BaseModel):
    version: str


# ── MTTX Dashboard Queries ────────────────────────────────────────────────────
# Query 1: Case history events — MTTA/MTTR + assignee timeline
MTTX_QUERY_HISTORY = """
$case_history_case_id = case_history.case_response_platform_info.case_id
$case_history_case_activity = case_history.case_activity
$case_history_case_event_time = case_history.event_time.seconds
$case_history_stage = case_history.stage
$case_history_status = case_history.status
$case_history_assignee_email = case_history.assignee.email
$case_history_assignee_name = case_history.assignee.name
match: $case_history_case_id, $case_history_case_activity, $case_history_case_event_time, $case_history_stage, $case_history_status, $case_history_assignee_email, $case_history_assignee_name
order: $case_history_case_id desc
limit: 10000
"""

# Query 2: Case + alert info — MTTD + alert/rule names
# MTTD = case.create_time - earliest alert event_timestamp
# We try two timestamp fields; Python picks whichever is valid.
MTTX_QUERY_CASE = """
$case_id = case.response_platform_info.response_platform_id
match: $case_id
outcome:
    $created_time         = max(case.create_time.seconds)
    $window_start_ts      = max(case.alerts.metadata.time_window.start_time.seconds)
    $detection_time_ts    = max(case.alerts.metadata.detection_time.seconds)
    $raw_event_ts         = max(case.alerts.metadata.collection_elements.references.event.metadata.event_timestamp.seconds)
    $alert_created_ts     = max(case.alerts.metadata.created_time.seconds)
    $detection_rule_name  = array_distinct(case.alerts.metadata.detection.rule_name)
    $alert_names          = array_distinct(case.alerts.metadata.detection.display_name)
    $soar_source_rule     = array_distinct(case.alerts.metadata.soar_alert_metadata.source_rule)
    $soar_product         = array_distinct(case.alerts.metadata.soar_alert_metadata.product)
    $soar_source_system   = array_distinct(case.alerts.metadata.soar_alert_metadata.source_system)
    $alert_types          = array_distinct(case.alerts.metadata.type)
    $case_display_name    = array_distinct(case.display_name)
    $alert_count          = count(case.alerts.metadata.id)
    $case_priority        = array_distinct(case.priority)
order: $case_id desc
limit: 5000
"""


# Query 3: Playbook names from case_history events.
# We use case_history.name (the activity display name) which contains playbook
# names in Chronicle deployments. case_history.description does not exist;
# valid fields: name, case_response_platform_info, event_time, stage, assignee,
# priority, status, incident, important, sla_type, case_activity,
# agent_investigation_state, alert_count.
# Completely non-fatal — if the field doesn't contain useful data the
# assignment_chain fallback still provides playbook names.
MTTX_QUERY_PB_COMMENTS = """
$case_id = case_history.case_response_platform_info.case_id
$pb_desc = case_history.name
$activity = case_history.case_activity
match: $case_id
outcome:
    $pb_descs = array_distinct($pb_desc)
    $activities = array_distinct($activity)
order: $case_id desc
limit: 5000
"""

MTTX_QUERY_LOG_TYPES = """
metadata.log_type != ""
$log_type = metadata.log_type
match: $log_type
outcome:
  $count = count(metadata.id)
order: $count desc
limit: 20
"""

MTTX_QUERY_INGESTION_GB = """
ingestion.component = "Ingestion API"
outcome:
    $total_gb = math.round(sum(ingestion.log_volume) / math.pow(1000, 3), 4)
"""


app = FastAPI(title="MTTX Dashboard")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])
api_router = APIRouter()



def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()


# ── MTTX Background Pre-Cache ─────────────────────────────────────────────────
def _months_to_precache():
    """Return list of (start_date, end_date) strings for last 3 calendar months."""
    now = datetime.now(timezone.utc)
    months = []
    for offset in range(3):
        # step back 'offset' months from current
        year  = now.year
        month = now.month - offset
        while month <= 0:
            month += 12
            year  -= 1
        import calendar
        last_day = calendar.monthrange(year, month)[1]
        months.append((
            f"{year}-{month:02d}-01",
            f"{year}-{month:02d}-{last_day:02d}",
        ))
    return months


def _precache_all_tenants():
    """Run MTTX analysis for every tenant × (last 3 months) if cache is stale."""
    if not SECOPS_SDK_AVAILABLE:
        return
    try:
        db = SessionLocal()
        tenants = db.query(Tenant).all()
        db.close()
    except Exception as e:
        logging.warning(f"MTTX precache: cannot read tenants: {e}")
        return

    now_utc   = datetime.now(timezone.utc)
    max_age_s = 600   # re-cache if older than 10 minutes

    # Last 3 calendar months + rolling 7-day window (always kept fresh)
    _seven = ((now_utc - timedelta(days=6)).strftime("%Y-%m-%d"), now_utc.strftime("%Y-%m-%d"))
    _windows = _months_to_precache() + [_seven]

    for tenant in tenants:
        for start_d, end_d in _windows:
            try:
                db = SessionLocal()
                existing = (
                    db.query(MttxRun)
                    .filter(
                        MttxRun.tenant_id == tenant.id,
                        MttxRun.start_date == start_d,
                        MttxRun.end_date   == end_d,
                    )
                    .order_by(MttxRun.id.desc())
                    .first()
                )
                if existing and existing.run_at:
                    try:
                        age_s = (now_utc - datetime.fromisoformat(existing.run_at)).total_seconds()
                    except Exception:
                        age_s = 9999999
                    if age_s < max_age_s:
                        db.close()
                        logging.info(f"MTTX precache: {start_d}→{end_d} tenant={tenant.id} OK ({int(age_s/60)}m old)")
                        continue  # cache still fresh
                db.close()

                logging.info(f"MTTX precache: running {start_d}→{end_d} for tenant {tenant.id} ({tenant.name})")
                s_time = datetime.fromisoformat(start_d).replace(tzinfo=timezone.utc)
                e_time = (datetime.fromisoformat(end_d).replace(tzinfo=timezone.utc)
                          + timedelta(days=1) - timedelta(seconds=1))
                eff_days = (e_time - s_time).days + 1
                result   = _mttx_live_run(tenant, eff_days, s_time, e_time)

                run_at = datetime.now(timezone.utc).isoformat()
                db = SessionLocal()
                run = MttxRun(
                    tenant_id=tenant.id, days=eff_days,
                    start_date=start_d, end_date=end_d,
                    run_at=run_at,
                    result_json=json.dumps(result),
                    is_demo=False,
                )
                db.add(run); db.commit()
                db.close()
                logging.info(f"MTTX precache: saved {start_d}→{end_d} tenant={tenant.id} ({len(result.get('alerts', []))} cases)")

            except Exception as e:
                logging.warning(f"MTTX precache: tenant={tenant.id} {start_d}→{end_d} failed: {e}")
                try: db.close()
                except Exception: pass


def _precache_loop():
    """Daemon thread: wait 30s on startup, then re-cache every 5 minutes."""
    time.sleep(30)
    while True:
        try:
            _precache_all_tenants()
        except Exception as e:
            logging.warning(f"MTTX precache loop error: {e}")
        time.sleep(300)   # 5 minutes between full passes


@app.on_event("startup")
def start_mttx_precache():
    if SECOPS_SDK_AVAILABLE:
        t = threading.Thread(target=_precache_loop, daemon=True, name="mttx-precache")
        t.start()
        logging.info("MTTX background pre-cache thread started (first run in 90s)")


@api_router.get("/version", response_model=VersionResponse)
def get_version():
    return {"version": VERSION}


@api_router.get("/tenants", response_model=List[TenantResponse])
def read_tenants(db: Session = Depends(get_db)):
    try:
        tenants = db.query(Tenant).all()
        logging.info(f"GET /tenants → {len(tenants)} tenant(s) from {_DB_PATH}")
        return tenants
    except Exception as exc:
        logging.error(f"GET /tenants SQLAlchemy hata: {exc} — fallback to raw sqlite3")
        import sqlite3 as _sq
        rows = []
        try:
            con = _sq.connect(_DB_PATH)
            for row in con.execute("SELECT id,name,guid,region,gcp_project_id,base_url FROM tenants"):
                rows.append({
                    "id": row[0], "name": row[1], "guid": row[2],
                    "region": row[3], "gcp_project_id": row[4], "base_url": row[5]
                })
            con.close()
        except Exception as exc2:
            logging.error(f"GET /tenants sqlite3 fallback da hata: {exc2}")
        return rows


@api_router.post("/tenants", response_model=TenantResponse, status_code=201)
def create_tenant(tenant: TenantCreate, response: Response, db: Session = Depends(get_db)):
    existing = db.query(Tenant).filter(Tenant.guid == tenant.guid).first()
    if existing:
        # Update the existing tenant (upsert)
        for key, value in tenant.model_dump().items():
            setattr(existing, key, value)
        db.commit()
        db.refresh(existing)
        response.status_code = 200
        return existing
    db_tenant = Tenant(**tenant.model_dump())
    db.add(db_tenant)
    db.commit()
    db.refresh(db_tenant)
    return db_tenant


@api_router.put("/tenants/{tenant_id}", response_model=TenantResponse)
def update_tenant(tenant_id: int, tenant: TenantUpdate, db: Session = Depends(get_db)):
    db_tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not db_tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    for key, value in tenant.model_dump().items():
        setattr(db_tenant, key, value)
    db.commit()
    db.refresh(db_tenant)
    return db_tenant


@api_router.delete("/tenants/{tenant_id}", status_code=204)
def delete_tenant(tenant_id: int, db: Session = Depends(get_db)):
    db_tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not db_tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    db.delete(db_tenant)
    db.commit()


@api_router.post("/tenants/{tenant_id}/test", response_model=TestConnectionResponse)
def test_connection(tenant_id: int, db: Session = Depends(get_db)):
    if not SECOPS_SDK_AVAILABLE:
        return {"status": "warning", "message": "SecOps SDK not installed. Running in demo mode."}
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    try:
        client = _secops_client()
        chronicle = client.chronicle(customer_id=tenant.guid,
                                     project_id=tenant.gcp_project_id, region=tenant.region)
        chronicle.list_feeds()
        return {"status": "success", "message": "Connection successful."}
    except Exception as e:
        return {"status": "failed", "message": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# MTTX — Mean Time to Detect / Acknowledge / Respond
# ══════════════════════════════════════════════════════════════════════════════

class MttxRun(Base):
    __tablename__ = "mttx_runs"
    id          = Column(Integer, primary_key=True, index=True)
    tenant_id   = Column(Integer, nullable=False)
    days        = Column(Integer, default=7)
    start_date  = Column(String, nullable=True)   # "YYYY-MM-DD" — set for month/range runs
    end_date    = Column(String, nullable=True)    # "YYYY-MM-DD" — set for month/range runs
    run_at      = Column(String, nullable=False)
    result_json = Column(Text, nullable=True)
    is_demo     = Column(Boolean, default=False)

# Make sure the new table exists (safe to call repeatedly)
Base.metadata.create_all(bind=engine)

# Add new columns to existing DB if upgrading from older schema
def _migrate_mttx_runs():
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            for col in ("start_date", "end_date"):
                try:
                    conn.execute(text(f"ALTER TABLE mttx_runs ADD COLUMN {col} TEXT"))
                    conn.commit()
                except Exception:
                    pass  # column already exists
    except Exception as e:
        logging.warning(f"mttx_runs migration: {e}")

_migrate_mttx_runs()


class MttxRunRequest(BaseModel):
    tenant_id: int
    days: int = 7
    start_date: Optional[str] = None  # "YYYY-MM-DD"
    end_date: Optional[str] = None    # "YYYY-MM-DD"


# ── Time helpers ──────────────────────────────────────────────────────────────
def _parse_ts(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        s = s.rstrip("Z")
        if "." in s:
            s = s[:s.index(".")+7]
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _minutes(delta) -> Optional[float]:
    if delta is None:
        return None
    return round(delta.total_seconds() / 60, 1)


def _fmt_dur(minutes: Optional[float]) -> str:
    if minutes is None:
        return "—"
    if minutes < 60:
        return f"{minutes:.0f}m"
    if minutes < 1440:
        return f"{minutes/60:.1f}h"
    return f"{minutes/1440:.1f}d"


# ── Aggregation ───────────────────────────────────────────────────────────────
def _mttx_aggregate(rows: list) -> dict:
    total       = len(rows)
    open_c      = sum(1 for r in rows if r["status"] == "OPEN")
    in_review_c = sum(1 for r in rows if r["status"] == "IN_REVIEW")
    closed_c    = sum(1 for r in rows if r["status"] == "CLOSED")

    def _avg(vals):
        v = [x for x in vals if x is not None]
        return round(statistics.mean(v), 1) if v else None
    def _median(vals):
        v = [x for x in vals if x is not None]
        return round(statistics.median(v), 1) if v else None
    def _p90(vals):
        v = sorted(x for x in vals if x is not None)
        return round(v[max(0, int(len(v) * 0.9) - 1)], 1) if v else None

    # ── Core metrics ─────────────────────────────────────────────────────────
    mttd_v         = [r["mttd_min"]        for r in rows]
    mtta_v         = [r["mtta_min"]        for r in rows]
    mttrc_v        = [r["mttr_case_min"]   for r in rows]
    mttp_v         = [r.get("mttp_min")    for r in rows]
    pb_handle_v    = [r.get("pb_handling_min")    for r in rows]
    human_handle_v = [r.get("human_handling_min") for r in rows]

    # MTTR split: with PB (automated+escalated) vs without PB (manual)
    mttrc_with_pb_v    = [r["mttr_case_min"] for r in rows
                          if r.get("resolution_type") in ("automated","escalated") and r["mttr_case_min"] is not None]
    mttrc_without_pb_v = [r["mttr_case_min"] for r in rows
                          if r.get("resolution_type") == "manual" and r["mttr_case_min"] is not None]

    # ── Automation / escalation breakdown ────────────────────────────────────
    automated = sum(1 for r in rows if r.get("resolution_type") == "automated")
    escalated = sum(1 for r in rows if r.get("resolution_type") == "escalated")
    manual    = sum(1 for r in rows if r.get("resolution_type") == "manual")
    pb_open   = sum(1 for r in rows if r.get("resolution_type") == "pb_open")

    closed_with_pb = automated + escalated
    automation_rate   = round(automated / closed_c * 100, 1) if closed_c else 0
    escalation_rate   = round(escalated / closed_with_pb * 100, 1) if closed_with_pb else 0
    pb_touch_rate     = round((automated + escalated + pb_open) / total * 100, 1) if total else 0

    # ── Daily trend ───────────────────────────────────────────────────────────
    daily = {}
    for r in rows:
        day = r["det_time"][:10]
        if day not in daily:
            daily[day] = {"date": day, "count": 0,
                          "mttd": [], "mtta": [], "mttr_case": [],
                          "mttp": [], "pb_handle": [], "human_handle": []}
        daily[day]["count"] += 1
        for k, fld in [("mttd","mttd_min"),("mtta","mtta_min"),
                        ("mttr_case","mttr_case_min"),("mttp","mttp_min"),
                        ("pb_handle","pb_handling_min"),("human_handle","human_handling_min")]:
            v = r.get(fld)
            if v is not None: daily[day][k].append(v)

    daily_list = [
        {"date": d["date"], "count": d["count"],
         "avg_mttd": _avg(d["mttd"]), "avg_mtta": _avg(d["mtta"]),
         "avg_mttr_case": _avg(d["mttr_case"]),
         "avg_mttp": _avg(d["mttp"]), "avg_pb_handle": _avg(d["pb_handle"]),
         "avg_human_handle": _avg(d["human_handle"])}
        for d in sorted(daily.values(), key=lambda x: x["date"])
    ]

    # ── By priority ───────────────────────────────────────────────────────────
    by_priority = {}
    for r in rows:
        p = r["priority"] or "UNKNOWN"
        if p not in by_priority:
            by_priority[p] = {"priority": p, "count": 0,
                              "mttd": [], "mtta": [], "mttr_case": [],
                              "mttr_with_pb": [], "mttr_without_pb": [],
                              "mttp": [], "pb_handle": [], "human_handle": []}
        by_priority[p]["count"] += 1
        for k, fld in [("mttd","mttd_min"),("mtta","mtta_min"),
                        ("mttr_case","mttr_case_min"),("mttp","mttp_min"),
                        ("pb_handle","pb_handling_min"),("human_handle","human_handling_min")]:
            v = r.get(fld)
            if v is not None: by_priority[p][k].append(v)
        # MTTR split
        rt = r.get("resolution_type")
        mv = r.get("mttr_case_min")
        if mv is not None:
            if rt in ("automated", "escalated"):
                by_priority[p]["mttr_with_pb"].append(mv)
            elif rt == "manual":
                by_priority[p]["mttr_without_pb"].append(mv)

    prio_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
    priority_list = sorted(
        [{"priority": p, "count": d["count"],
          "avg_mttd": _avg(d["mttd"]), "avg_mtta": _avg(d["mtta"]),
          "avg_mttr_case": _avg(d["mttr_case"]),
          "avg_mttr_with_pb": _avg(d["mttr_with_pb"]),
          "avg_mttr_without_pb": _avg(d["mttr_without_pb"]),
          "avg_mttp": _avg(d["mttp"]), "avg_pb_handle": _avg(d["pb_handle"]),
          "avg_human_handle": _avg(d["human_handle"])}
         for p, d in by_priority.items()],
        key=lambda x: prio_order.get(x["priority"], 9)
    )

    # ── By rule ───────────────────────────────────────────────────────────────
    by_rule = {}
    for r in rows:
        rn = r["rule_name"]
        if rn not in by_rule:
            by_rule[rn] = {"rule_name": rn, "count": 0, "auto": 0, "closed": 0,
                           "mttd": [], "mtta": [], "mttr_case": [],
                           "mttr_with_pb": [], "mttr_without_pb": [],
                           "mttp": [], "pb_handle": [], "human_handle": []}
        by_rule[rn]["count"] += 1
        rt = r.get("resolution_type")
        if r.get("status") == "CLOSED":
            by_rule[rn]["closed"] += 1
        if rt == "automated":
            by_rule[rn]["auto"] += 1
        for k, fld in [("mttd","mttd_min"),("mtta","mtta_min"),
                        ("mttr_case","mttr_case_min"),("mttp","mttp_min"),
                        ("pb_handle","pb_handling_min"),("human_handle","human_handling_min")]:
            v = r.get(fld)
            if v is not None: by_rule[rn][k].append(v)
        mv = r.get("mttr_case_min")
        if mv is not None:
            if rt in ("automated","escalated"): by_rule[rn]["mttr_with_pb"].append(mv)
            elif rt == "manual":               by_rule[rn]["mttr_without_pb"].append(mv)

    rule_list = sorted(
        [{"rule_name": rn, "count": d["count"],
          "auto_rate": round(d["auto"]/d["count"]*100, 1) if d["count"] else 0,
          "avg_mttd": _avg(d["mttd"]), "avg_mtta": _avg(d["mtta"]),
          "avg_mttr_case": _avg(d["mttr_case"]),
          "avg_mttr_with_pb": _avg(d["mttr_with_pb"]),
          "avg_mttr_without_pb": _avg(d["mttr_without_pb"]),
          "avg_mttp": _avg(d["mttp"]), "avg_pb_handle": _avg(d["pb_handle"]),
          "avg_human_handle": _avg(d["human_handle"])}
         for rn, d in by_rule.items()],
        key=lambda x: x["count"], reverse=True
    )

    # ── Priority × resolution cross-breakdown ────────────────────────────────
    PNORM = {"PRIORITY_CRITICAL":"CRITICAL","PRIORITY_HIGH":"HIGH",
              "PRIORITY_MEDIUM":"MEDIUM","PRIORITY_LOW":"LOW",
              "CRITICAL":"CRITICAL","HIGH":"HIGH","MEDIUM":"MEDIUM","LOW":"LOW"}
    by_res_prio = {}
    for r in rows:
        rt = r.get("resolution_type") or "open"
        p  = PNORM.get(r.get("priority",""), "UNKNOWN")
        if rt not in by_res_prio: by_res_prio[rt] = {}
        by_res_prio[rt][p] = by_res_prio[rt].get(p, 0) + 1

    # ── Resolution type breakdown ─────────────────────────────────────────────
    res_breakdown = [
        {"type": "automated", "label": "🤖 Automated",    "count": automated,
         "desc": "Playbook resolved, no human needed"},
        {"type": "escalated", "label": "⚡ Escalated",     "count": escalated,
         "desc": "Playbook → analyst handoff"},
        {"type": "manual",    "label": "👤 Manual",        "count": manual,
         "desc": "Analyst only, no playbook"},
        {"type": "pb_open",   "label": "⏳ PB In Progress","count": pb_open,
         "desc": "Playbook assigned, case still open"},
        {"type": "open",      "label": "🔓 Open",          "count": open_c - pb_open,
         "desc": "No assignment yet"},
    ]

    return {
        "total_alerts": total, "open": open_c, "in_review": in_review_c, "closed": closed_c,
        "resolved_pct": round(closed_c / total * 100, 1) if total else 0,
        # Core metrics
        "avg_mttd": _avg(mttd_v), "median_mttd": _median(mttd_v), "p90_mttd": _p90(mttd_v),
        "avg_mtta": _avg(mtta_v), "median_mtta": _median(mtta_v), "p90_mtta": _p90(mtta_v),
        "avg_mttr_case":       _avg(mttrc_v),        "p90_mttr_case":       _p90(mttrc_v),
        "avg_mttr_with_pb":    _avg(mttrc_with_pb_v), "p90_mttr_with_pb":    _p90(mttrc_with_pb_v),
        "avg_mttr_without_pb": _avg(mttrc_without_pb_v),"p90_mttr_without_pb":_p90(mttrc_without_pb_v),
        # Automation metrics
        "avg_mttp":           _avg(mttp_v),         "p90_mttp":           _p90(mttp_v),
        "avg_pb_handling":    _avg(pb_handle_v),    "p90_pb_handling":    _p90(pb_handle_v),
        "avg_human_handling": _avg(human_handle_v), "p90_human_handling": _p90(human_handle_v),
        # Rates
        "automation_rate":  automation_rate,
        "escalation_rate":  escalation_rate,
        "pb_touch_rate":    pb_touch_rate,
        "automated_count":  automated,
        "escalated_count":  escalated,
        "manual_count":     manual,
        # Breakdowns
        "daily": daily_list, "by_priority": priority_list, "by_rule": rule_list,
        "resolution_breakdown": res_breakdown,
        "by_resolution_priority": by_res_prio,
    }


# ── Mock data ─────────────────────────────────────────────────────────────────
_MTTX_RULES = [
    "Brute Force Login Attempt", "Lateral Movement via SMB", "Data Exfiltration via DNS",
    "Privilege Escalation Detected", "Suspicious PowerShell Execution", "C2 Communication Pattern",
    "Ransomware File Rename Pattern", "Credential Dumping via LSASS",
    "Unusual Admin Account Activity", "Port Scan Detected", "Phishing URL Click", "Malicious File Download",
]
# Keywords that identify SOAR/automation user accounts (case-insensitive, matched in name)
# e.g. @SOAR_Playbook, soar_playbook_user, automation_bot, etc.
_PB_ACCOUNT_KEYWORDS = frozenset({"soar", "playbook", "automation", "autoclose", "_bot", "runbook", "orchestrat"})

def _classify_assignee(email: str, name: str) -> str:
    """Return 'human' | 'playbook' | 'group' for a Chronicle assignee."""
    if email:
        return "human"                          # real email = individual human analyst
    n = name.lower().lstrip("@")
    if any(kw in n for kw in _PB_ACCOUNT_KEYWORDS):
        return "playbook"                       # @SOAR_Playbook, soar_user, etc.
    if name.startswith("@"):
        return "group"                          # @SOC_Analysts, @Administrator, etc.
    return "playbook"                           # no email, no @, no keyword = SOAR automation


_MTTX_PRIOS    = ["CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "MEDIUM", "LOW"]
_MTTX_STATUSES = ["OPEN", "IN_REVIEW", "CLOSED", "CLOSED", "CLOSED"]
_MTTX_VERDICTS = ["TRUE_POSITIVE", "TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN", ""]
_MTTX_ANALYSTS  = ["alice@corp.com", "bob@corp.com", "carol@corp.com"]
_MTTX_PLAYBOOKS = ["soar_playbook_v2", "auto_triage_pb", "enrichment_pb"]
_MTTX_RES_TYPES = ["automated", "automated", "escalated", "manual", "open"]  # weighted


def _mttx_mock_run(days: int = 7, tenant_name: str = "Demo Tenant") -> dict:
    now   = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    rows  = []

    for i in range(random.randint(45, 90)):
        det_ts   = start + timedelta(hours=random.uniform(0, days * 24))
        ev_ts    = det_ts - timedelta(minutes=random.uniform(2, 180))
        priority = random.choice(_MTTX_PRIOS)
        status   = random.choice(_MTTX_STATUSES)
        rule     = random.choice(_MTTX_RULES)
        res_type = random.choice(_MTTX_RES_TYPES)
        if status != "CLOSED" and res_type in ("automated", "escalated", "manual"):
            res_type = "pb_open" if random.random() < 0.5 else "open"

        base_mtta = {"CRITICAL": 15, "HIGH": 45, "MEDIUM": 120, "LOW": 360}.get(priority, 120)
        base_mttr = {"CRITICAL": 120, "HIGH": 360, "MEDIUM": 720, "LOW": 1440}.get(priority, 720)
        mtta  = round(random.uniform(base_mtta * 0.3, base_mtta * 2.5), 1) if status in ("IN_REVIEW", "CLOSED") else None
        mttr_a= round(random.uniform(base_mttr * 0.4, base_mttr * 2.0), 1) if status == "CLOSED" else None
        mttr_c= round(mttr_a * random.uniform(0.6, 1.1), 1) if mttr_a else None

        # Automation metrics
        has_pb    = res_type in ("automated", "escalated", "pb_open")
        has_human = res_type in ("escalated", "manual")
        mttp          = round(random.uniform(2, 30), 1)  if has_pb    else None
        pb_handling   = round(random.uniform(5, 120), 1) if has_pb    else None
        human_handling= round(random.uniform(30, 480), 1) if has_human else None

        # Build demo timeline
        t0 = det_ts
        timeline = [{"time_iso": t0.isoformat(), "activity": "Case Created", "assignee": None, "assignee_type": None, "stage": "NEW"}]
        if has_pb:
            t_pb = t0 + timedelta(minutes=mttp)
            pb_name = random.choice(_MTTX_PLAYBOOKS)
            timeline.append({"time_iso": t_pb.isoformat(), "activity": "Assigned", "assignee": pb_name, "assignee_type": "playbook", "stage": "IN_PROGRESS"})
        if has_human:
            t_h = t0 + timedelta(minutes=(mttp or 0) + (pb_handling or 0))
            human_name = random.choice(_MTTX_ANALYSTS)
            timeline.append({"time_iso": t_h.isoformat(), "activity": "Assignee Changed", "assignee": human_name, "assignee_type": "human", "stage": "IN_PROGRESS"})
        if status == "CLOSED":
            t_close = t0 + timedelta(minutes=mttr_c or base_mttr)
            timeline.append({"time_iso": t_close.isoformat(), "activity": "Case Closed", "assignee": None, "assignee_type": None, "stage": "CLOSED"})

        case_id  = f"CASE-{10000 + i}" if status in ("IN_REVIEW", "CLOSED") else None
        chain    = []
        if has_pb:   chain.append({"assignee": random.choice(_MTTX_PLAYBOOKS), "type": "playbook"})
        if has_human:chain.append({"assignee": random.choice(_MTTX_ANALYSTS),  "type": "human"})

        rows.append({
            "alert_id":           f"alert-{i:05d}",
            "case_id":            case_id,
            "case_display":       f"[{priority}] {rule}" if case_id else "",
            "rule_name":          rule,
            "rule_id":            f"ru_{i:08x}",
            "status":             status,
            "priority":           priority,
            "verdict":            random.choice(_MTTX_VERDICTS) if status == "CLOSED" else "",
            "det_time":           det_ts.isoformat(),
            "event_time":         ev_ts.isoformat(),
            "case_stage":         {"OPEN": "OPEN", "IN_REVIEW": "IN_PROGRESS", "CLOSED": "CLOSED"}.get(status, "OPEN"),
            "case_close_reason":  random.choice(["MALICIOUS", "NOT_MALICIOUS", "INCONCLUSIVE"]) if status == "CLOSED" else "",
            "resolution_type":    res_type,
            "assigned_to":        (chain[-1]["assignee"] if chain else ""),
            "has_pb":             has_pb,
            "has_human":          has_human,
            "mttd_min":           _minutes(det_ts - ev_ts),
            "mtta_min":           mtta,
            "mttr_alert_min":     mttr_a,
            "mttr_case_min":      mttr_c,
            "mttp_min":           mttp,
            "pb_handling_min":    pb_handling,
            "human_handling_min": human_handling,
            "alert_names":        [f"Alert: {rule}", f"Variant-{random.randint(1,3)}"],
            "assignment_chain":   chain,
            "timeline":           timeline,
        })

    summary = _mttx_aggregate(rows)
    demo_log_types = [
        {"log_type": "FORTINET_FIREWALL", "count": 133},
        {"log_type": "WINEVTLOG",         "count": 86},
        {"log_type": "AUDITD",            "count": 79},
        {"log_type": "NIX_SYSTEM",        "count": 73},
        {"log_type": "WINDOWS_DNS",       "count": 56},
        {"log_type": "REDHAT_OPENSHIFT",  "count": 34},
        {"log_type": "FORCEPOINT_DLP",    "count": 21},
        {"log_type": "CS_EDR",            "count": 6},
    ]
    return {
        "tenant_name": tenant_name,
        "days": days,
        "start_time": start.isoformat(),
        "end_time":   now.isoformat(),
        "is_demo":    True,
        "summary":    summary,
        "log_types":  demo_log_types,
        "alerts":     sorted(rows, key=lambda r: r["det_time"], reverse=True),
    }


# ── Dashboard query result parser ─────────────────────────────────────────────
def _dq_to_rows(result: dict) -> list[dict]:
    """Convert execute_dashboard_query result → list of row dicts."""
    cols = result.get("results", [])
    if not cols:
        return []
    headers = [c.get("column", f"col{i}") for i, c in enumerate(cols)]
    num_rows = len(cols[0].get("values", []))
    rows = []
    for r in range(num_rows):
        row = {}
        for h, col in zip(headers, cols):
            item = col.get("values", [])[r] if r < len(col.get("values", [])) else {}
            # list type (array_distinct returns list)
            if "list" in item and isinstance(item["list"].get("values"), list):
                parts = []
                for entry in item["list"]["values"]:
                    k = next((k2 for k2 in entry if k2 != "metadata"), None)
                    if k and entry[k]:
                        parts.append(str(entry[k]))
                row[h] = parts
            elif "value" in item:
                inner = item["value"]
                k = next((k2 for k2 in inner if k2 != "metadata"), None)
                row[h] = inner[k] if k else None
            else:
                row[h] = None
        rows.append(row)
    return rows


# ── Live Chronicle fetch via dashboard queries ────────────────────────────────
def _mttx_live_run(tenant: Tenant, days: int, start_time: datetime = None, end_time: datetime = None) -> dict:
    now   = end_time   or datetime.now(timezone.utc)
    start = start_time or (now - timedelta(days=days))
    if start_time and end_time:
        interval = {"time_window": {"start_time": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                    "end_time":   now.strftime("%Y-%m-%dT%H:%M:%SZ")}}
    else:
        interval = {"relativeTime": {"timeUnit": "DAY", "startTimeVal": str(days)}}

    # Chronicle client init — no base_url kwarg
    client    = _secops_client()
    chronicle = client.chronicle(customer_id=tenant.guid,
                                 project_id=tenant.gcp_project_id,
                                 region=tenant.region)

    # ── Adaptive chunked query helper ─────────────────────────────────────────
    def _query_chunked(query: str, s: datetime, e: datetime,
                       row_limit: int, chunk_days: int = 7) -> list:
        """Run a dashboard query in time chunks. If a chunk returns >= row_limit rows
        (indicating the limit was hit and data may be truncated), automatically halve
        the chunk and retry — ensuring no cases are missed regardless of volume."""
        MIN_CHUNK_DAYS = 1.0 / 24.0   # split down to 1 hour: even sub-day density shouldn't hit the 10000 limit
        results = []
        cur = s
        while cur < e:
            nxt = min(cur + timedelta(days=chunk_days), e)
            ivl = {"time_window": {
                "start_time": cur.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "end_time":   nxt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }}
            chunk = _dq_to_rows(chronicle.execute_dashboard_query(query=query, interval=ivl))
            if len(chunk) >= row_limit and chunk_days > MIN_CHUNK_DAYS:
                # Limit hit — split this chunk further (down to sub-day / hourly) to avoid missing data
                half = max(MIN_CHUNK_DAYS, chunk_days / 2.0)
                logging.info(f"MTTX chunk {cur.isoformat()}→{nxt.isoformat()} hit {row_limit} limit, re-running in {half*24:.1f}h sub-chunks")
                chunk = _query_chunked(query, cur, nxt, row_limit=row_limit, chunk_days=half)
            results.extend(chunk)
            cur = nxt
        return results

    # ── Query 1: case_history (MTTA + MTTR) ───────────────────────────────────
    period_days = (now - start).days
    logging.info(f"MTTX: running case_history query for tenant {tenant.guid} ({days}d, adaptive chunks)")
    # ALWAYS run chunked: even <=7 days could hit the 10000-row cap in a single query and drop older days
    # (the case list showed only the newest ~2 days). Chunks are split down to the hour when needed.
    history_rows = _query_chunked(MTTX_QUERY_HISTORY, start, now, row_limit=10000, chunk_days=7)

    _hist_ids = sorted(set(r.get("case_history_case_id","") for r in history_rows if r.get("case_history_case_id")), reverse=True)
    logging.info(f"MTTX: case_history returned {len(history_rows)} rows, {len(_hist_ids)} unique cases, top5_ids={_hist_ids[:5]}")

    # ── Query 2: case + alert events (MTTD) ───────────────────────────────────
    logging.info("MTTX: running case MTTD query")
    # Always chunked: a single query can drop older cases as the count grows (5000+).
    _raw_case_rows = _query_chunked(MTTX_QUERY_CASE, start, now, row_limit=5000, chunk_days=7)
    # De-duplicate by case_id (same case can appear across chunk boundaries)
    _seen_cids: set = set()
    case_rows = []
    for _cr in _raw_case_rows:
        _cid = _cr.get("case_id")
        if _cid and _cid not in _seen_cids:
            _seen_cids.add(_cid)
            case_rows.append(_cr)
        elif not _cid:
            case_rows.append(_cr)
    logging.info(f"MTTX: case MTTD query returned {len(case_rows)} rows")
    # Debug: log first 3 rows so we can see what timestamp fields are returning
    # Alert type distribution
    from collections import Counter
    _type_counts = Counter()
    for _r in case_rows:
        for _t in (_r.get("alert_types") or ["UNKNOWN"]):
            _type_counts[_t or "UNKNOWN"] += 1
    logging.info(f"MTTX DEBUG alert_type distribution: {dict(_type_counts)}")

    # First 3 rows detail
    for _dbg in case_rows[:2]:
        logging.info(
            f"MTTX DEBUG [{(_dbg.get('alert_types') or ['?'])[0]}] id={_dbg.get('case_id')} "
            f"win_start={_dbg.get('window_start_ts')} "
            f"soar_src_rule={_dbg.get('soar_source_rule')} soar_product={_dbg.get('soar_product')} "
            f"rule_names={_dbg.get('detection_rule_name')} alert_count={_dbg.get('alert_count')}"
        )
    _coll = next((r for r in case_rows if (r.get("alert_types") or [""])[0] == "COLLECTION_TYPE_UNSPECIFIED"), None)
    if _coll:
        logging.info(f"MTTX DEBUG COLLECTION_TYPE full: { {k:v for k,v in _coll.items()} }")

    # ── Build per-case metric dicts from case_history ─────────────────────────
    # Group history events by case_id
    by_case: dict[str, list] = {}
    for r in history_rows:
        cid = str(r.get("case_history_case_id") or "")
        if cid:
            by_case.setdefault(cid, []).append(r)

    # Build MTTD enrichment map from case query
    mttd_map: dict[str, dict] = {}
    for r in case_rows:
        cid = str(r.get("case_id") or "")
        if cid:
            mttd_map[cid] = r

    # ── Fetch per-case alert names + event timestamps via legacyAlertsFullDetails ─
    # Uses SQLite cache (mttx_alert_cache table) to avoid repeated API calls.
    # Rate-limited to avoid 429s: 3 workers, 0.25s sleep between requests.
    import concurrent.futures as _cf
    import time as _time
    import json as _json

    case_alert_names_map: dict[str, list[str]] = {}
    case_event_ts_map:    dict[str, int]       = {}

    try:
        _base_v1a   = chronicle.base_url("v1alpha")
        _inst       = chronicle.instance_id
        _alerts_url = f"{_base_v1a}/{_inst}/legacySdk:legacyAlertsFullDetails"
        all_case_ids = list(mttd_map.keys())

        # ── Load SQLite cache (stored in the app's own DB, not a separate file) ──
        _db_path = _DB_PATH
        import sqlite3 as _sqlite3
        with _sqlite3.connect(_db_path) as _dbc:
            _dbc.execute("""
                CREATE TABLE IF NOT EXISTS mttx_alert_cache (
                    case_id      TEXT PRIMARY KEY,
                    alert_names  TEXT,
                    event_ts     INTEGER,
                    cached_at    INTEGER
                )
            """)
            _dbc.commit()
            _rows = _dbc.execute(
                "SELECT case_id, alert_names, event_ts FROM mttx_alert_cache"
            ).fetchall()

        _cached_ids = set()
        for _cid, _anames, _ets in _rows:
            _cached_ids.add(_cid)
            if _anames:
                try:
                    case_alert_names_map[_cid] = _json.loads(_anames)
                except Exception:
                    pass
            if _ets:
                case_event_ts_map[_cid] = _ets

        # ── Fetch only uncached cases, max 200 per run ─────────────────────────
        _uncached = [cid for cid in all_case_ids if cid not in _cached_ids]
        _to_fetch = _uncached[:200]   # max 200 per dashboard run
        logging.info(
            f"MTTX alert cache: {len(_cached_ids)} cached, "
            f"{len(_uncached)} uncached, fetching {len(_to_fetch)}"
        )

        _new_cache: list[tuple] = []
        _lock = __import__("threading").Lock()

        def _fetch_one(cid: str):
            _time.sleep(0.25)   # rate limit: ~4 req/s per worker × 3 workers = ~12 req/s
            try:
                r = chronicle._session.get(
                    _alerts_url,
                    params={"caseId": cid, "format": "snake"},
                    timeout=20,
                )
                if r.status_code != 200:
                    return cid, [], None
                data = r.json()
                events = []
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            events.extend(item.get("security_events") or [])
                elif isinstance(data, dict):
                    events = data.get("security_events") or []

                names, ts_list = [], []
                for ev in events:
                    if not isinstance(ev, dict):
                        continue
                    n = (ev.get("name") or ev.get("display_name")
                         or ev.get("alert_name") or "")
                    if n and n not in names:
                        names.append(n)
                    raw_ts = ev.get("start_time")
                    if raw_ts:
                        try:
                            ts_s = int(raw_ts) // 1000
                            if ts_s > 946684800:
                                ts_list.append(ts_s)
                        except Exception:
                            pass
                earliest = min(ts_list) if ts_list else None
                return cid, names, earliest
            except Exception:
                return cid, [], None

        if _to_fetch:
            with _cf.ThreadPoolExecutor(max_workers=3) as _pool:
                for _fut in _cf.as_completed(
                    {_pool.submit(_fetch_one, cid): cid for cid in _to_fetch}
                ):
                    _cid, _names, _ts = _fut.result()
                    if _names:
                        case_alert_names_map[_cid] = _names
                    if _ts:
                        case_event_ts_map[_cid] = _ts
                    _new_cache.append((
                        _cid,
                        _json.dumps(_names) if _names else None,
                        _ts,
                        int(_time.time()),
                    ))

            # Persist new entries to cache
            if _new_cache:
                with _sqlite3.connect(_db_path) as _dbc:
                    _dbc.executemany(
                        "INSERT OR REPLACE INTO mttx_alert_cache "
                        "(case_id, alert_names, event_ts, cached_at) VALUES (?,?,?,?)",
                        _new_cache,
                    )
                    _dbc.commit()

        logging.info(
            f"MTTX alerts: {len(case_alert_names_map)} with names, "
            f"{len(case_event_ts_map)} with timestamps, "
            f"{len(_new_cache)} newly fetched"
        )
    except Exception as _detail_err:
        logging.warning(f"MTTX alert cache/fetch failed (non-fatal): {_detail_err}")

    def _ev_time(e):
        t = e.get("case_history_case_event_time")
        try: return float(t) if t is not None else 0.0
        except: return 0.0

    start_ts = start.timestamp()
    now_ts   = now.timestamp()

    rows = []
    for case_id, events in by_case.items():
        events_sorted = sorted(events, key=_ev_time)

        # ── Key timestamps ────────────────────────────────────────────────────
        t_create       = None
        t_first_action = None
        t_close        = None
        t_pb_first     = None   # first PB assignment (pre-close → MTTP computable)
        t_human_first  = None   # first individual human assignment
        pb_seen        = False  # True even if PB assignment happened post-close
        last_stage     = ""
        last_assignee  = ""

        # ── Assignment / timeline history ─────────────────────────────────────
        timeline       = []
        seen_assignees = []   # ordered unique: (assignee_str, type)

        label_map = {
            "CREATE_CASE":     "Case Created",
            "CLOSE_CASE":      "Case Closed",
            "STAGE_CHANGE":    "Stage Changed",
            "ASSIGN_CASE":     "Assigned",
            "ASSIGNEE_CHANGE": "Assignee Changed",
            "REOPEN_CASE":     "Reopened",
            "ADD_COMMENT":     "Comment Added",
            "PRIORITY_CHANGE": "Priority Changed",
        }

        for ev in events_sorted:
            act             = str(ev.get("case_history_case_activity") or "")
            ts              = _ev_time(ev)
            stage           = str(ev.get("case_history_stage") or "")
            assignee_email  = str(ev.get("case_history_assignee_email") or "")
            assignee_name   = str(ev.get("case_history_assignee_name")  or "")

            # ── Assignee type detection ────────────────────────────────────
            # Uses _classify_assignee() which keyword-matches SOAR accounts
            # even when they carry a leading "@" (e.g. @SOAR_Playbook)
            atype        = _classify_assignee(assignee_email, assignee_name) if (assignee_email or assignee_name) else None
            is_human     = atype == "human"
            is_pb        = atype == "playbook"
            is_group     = atype == "group"
            assignee_str = assignee_email or assignee_name

            if ts == 0:
                continue

            if act == "CREATE_CASE" and t_create is None:
                t_create = ts
            if act in ("ASSIGN_CASE","ASSIGNEE_CHANGE") \
                    and t_create and ts > t_create and t_first_action is None:
                t_first_action = ts
            if act == "CLOSE_CASE" and t_close is None:
                t_close = ts

            # Track playbook vs human assignment times
            if act in ("ASSIGN_CASE", "ASSIGNEE_CHANGE") and assignee_str:
                if is_pb:
                    pb_seen = True
                    # Only set t_pb_first if it happened BEFORE close (pre-close = MTTP computable)
                    # Post-close PB assignment (current SOAR pattern) still sets pb_seen
                    # so resolution_type can be "automated", but MTTP will be None
                    if t_pb_first is None and (t_close is None or ts <= t_close):
                        t_pb_first = ts
                elif is_human and t_human_first is None:
                    t_human_first = ts
                # groups (@SOC_Analysts) count for MTTA but not MTTP/human_handling

            if stage:
                last_stage = stage
            if assignee_str:
                last_assignee = assignee_str
                atype = "human" if is_human else ("playbook" if is_pb else "group")
                entry = (assignee_str, atype)
                if entry not in seen_assignees:
                    seen_assignees.append(entry)

            atype_tl = ("human" if is_human else ("playbook" if is_pb else ("group" if is_group else None))) if assignee_str else None
            timeline.append({
                "time_iso":      datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                "activity":      label_map.get(act, act),
                "assignee":      assignee_str or None,
                "assignee_type": atype_tl,
                "stage":         stage or None,
            })

        if t_create is None:
            # Fallback: use created_time from MTTX_QUERY_CASE (case_history may lag)
            _fallback = mttd_map.get(case_id, {}).get("created_time")
            try:
                t_create = float(_fallback) if _fallback else None
            except Exception:
                t_create = None
        if t_create is None:
            continue
        if t_create < start_ts or t_create > now_ts:
            continue

        det_dt = datetime.fromtimestamp(t_create, tz=timezone.utc)

        def _min(a, b):
            return round((b - a) / 60, 1) if (a and b and b >= a) else None

        # ── Core metrics ──────────────────────────────────────────────────────
        mtta       = _min(t_create, t_first_action)
        mttr_case  = _min(t_create, t_close)
        status     = "CLOSED" if t_close else "OPEN"

        # ── Automation metrics ────────────────────────────────────────────────
        mttp          = _min(t_create, t_pb_first)     # time-to-playbook
        pb_handling   = _min(t_pb_first, t_human_first or t_close)  # PB hold time
        human_handling= _min(t_human_first, t_close)  # human hold time after escalation

        # Resolution type
        # pb_seen: True even if @SOAR_Playbook assignment came post-close
        # t_pb_first: only set when assignment happened BEFORE close (enables MTTP)
        has_pb    = pb_seen                   # any PB involvement (pre or post close)
        has_human = t_human_first is not None # individual human was assigned
        if status == "CLOSED":
            if has_pb and not has_human:
                resolution_type = "automated"    # PB handled it, no individual human
            elif has_pb and has_human:
                resolution_type = "escalated"    # PB started, human finished
            else:
                resolution_type = "manual"       # human only (queue → individual → close)
        else:
            resolution_type = "pb_open" if has_pb else "open"

        # ── MTTD + alert names from case query ───────────────────────────────
        # MTTD = case_create_time − detection window start (= rule lookback start)
        # For a 5h-window rule this gives MTTD ≥ 5h — meaningful detection latency.
        # Fallback: use detection_time (when rule fired ≈ case create) → MTTD ≈ 0–5 min
        mttd_data    = mttd_map.get(case_id, {})
        t_created_c     = mttd_data.get("created_time")
        t_win_start     = mttd_data.get("window_start_ts")
        t_raw_event     = mttd_data.get("raw_event_ts")
        t_detect        = mttd_data.get("detection_time_ts")
        t_alert_create  = mttd_data.get("alert_created_ts")
        # Timestamp from legacyAlertsFullDetails (start_time in ms → seconds)
        t_legacy_event  = str(case_event_ts_map[case_id]) if case_id in case_event_ts_map else None
        mttd = None
        if t_created_c:
            try:
                c = float(t_created_c)
                # Priority: rule window start → raw event → detection time → alert create → legacy SDK event
                for e_raw in [t_win_start, t_raw_event, t_detect, t_alert_create, t_legacy_event]:
                    if not e_raw:
                        continue
                    e = float(e_raw)
                    if e > 946684800 and 0 < (c - e) <= 90 * 86400:
                        mttd = round((c - e) / 60, 1)
                        break
            except Exception:
                pass

        def _join_list(v, fallback="—"):
            if isinstance(v, list): return ", ".join(v) if v else fallback
            return str(v) if v else fallback

        _det_rule_names = [r for r in (mttd_data.get("detection_rule_name") or []) if r]
        _disp           = [a for a in (mttd_data.get("alert_names")         or []) if a]
        _soar_rules     = [a for a in (mttd_data.get("soar_source_rule")    or []) if a]
        _cdisplay       = [a for a in (mttd_data.get("case_display_name")   or []) if a]
        case_display    = _cdisplay

        # Extract alert name from case display name "ALERT_NAME - CASE_ID" pattern
        _from_display = []
        if _cdisplay:
            _suffix = f" - {case_id}"
            _from_display = [n[:-len(_suffix)] if n.endswith(_suffix) else n
                             for n in _cdisplay if n and n != case_id]

        # Priority: case detail API (actual alert names) →
        #           detection.display_name → soar.source_rule →
        #           case display name strip → detection.rule_name
        _api_names = case_alert_names_map.get(case_id, [])
        alert_names = (_api_names
                       or _disp
                       or _soar_rules
                       or _from_display
                       or _det_rule_names)

        rows.append({
            # ── identifiers ──────────────────────────────────────────────────
            "alert_id":           case_id,
            "case_id":            case_id,
            "case_display":       _join_list(case_display, case_id),
            "rule_name":          _join_list(_det_rule_names or _from_display, "Unknown Rule"),
            "rule_id":            "",
            # ── state ────────────────────────────────────────────────────────
            "status":             status,
            "priority":           (((mttd_data.get("case_priority") or ["UNKNOWN"])[0]) if isinstance(mttd_data.get("case_priority"), list) else (mttd_data.get("case_priority") or "UNKNOWN")).upper(),
            "verdict":            "",
            "case_stage":         last_stage,
            "case_close_reason":  "",
            "resolution_type":    resolution_type,
            # ── times ────────────────────────────────────────────────────────
            "det_time":           det_dt.isoformat(),
            "event_time":         None,
            # ── core metrics (minutes) ────────────────────────────────────────
            "mttd_min":           mttd,
            "mtta_min":           mtta,
            "mttr_case_min":      mttr_case,
            # ── automation metrics (minutes) ──────────────────────────────────
            "mttp_min":           mttp,           # time-to-playbook
            "pb_handling_min":    pb_handling,    # how long PB held the case
            "human_handling_min": human_handling, # human time after escalation
            # ── assignment ───────────────────────────────────────────────────
            "assigned_to":        last_assignee,
            "has_pb":             has_pb,
            "pb_pre_close":       t_pb_first is not None,   # PB assigned BEFORE close → MTTP valid
            "has_human":          has_human,
            # assignment_chain: [{assignee, type}] ordered
            "assignment_chain":   [{"assignee": a, "type": t} for a, t in seen_assignees],
            # ── enriched detail fields ────────────────────────────────────────
            "alert_names":        alert_names if isinstance(alert_names, list) else ([alert_names] if alert_names else []),
            "timeline":           timeline,
        })

    logging.info(f"MTTX: built {len(rows)} case rows")

    # ── Exclude internal/noise cases — CONFIGURABLE (from the DB; NOT hard-coded) ──
    _EXCLUDE_KEYWORDS = _load_exclusion_keywords()
    def _is_excluded(row):
        # Check case_display, rule_name, AND alert_names so we catch cases
        # where case_display is empty but the rule/alert name contains noise keywords
        _parts = [
            row.get("case_display") or "",
            row.get("rule_name") or "",
        ]
        _an = row.get("alert_names")
        if isinstance(_an, list):
            _parts.extend(_an)
        elif _an:
            _parts.append(str(_an))
        name = " ".join(_parts).lower()
        return any(kw.lower() in name for kw in _EXCLUDE_KEYWORDS)

    before = len(rows)
    rows = [r for r in rows if not _is_excluded(r)]
    logging.info(f"MTTX: excluded {before - len(rows)} internal/noise cases, {len(rows)} remaining")

    # ── Supplement with list_cases REST API (real-time, no dashboard lag) ────────
    logging.info("MTTX supplement: starting...")
    try:
        _inst_sup = chronicle.instance_id
        _url = f"https://{tenant.region}-chronicle.googleapis.com/v1/{_inst_sup}/cases"
        logging.info(f"MTTX supplement URL: {_url}")
        # Fetch only 1 page (1000 most recent cases, sorted desc) – avoids 429 pagination issues
        _params = {"orderBy": "createTime desc", "pageSize": 1000}
        _r = chronicle._session.get(_url, params=_params)
        _r.raise_for_status()
        live_cases = _r.json().get("cases", [])
        # Build existing_ids from ALL rows before exclusion: excluded cases should also be skipped
        existing_ids = {r["case_id"] for r in rows}
        # Also include the 2454 pre-exclusion IDs so we don't re-add excluded noise cases
        _all_case_ids = set(by_case.keys())
        existing_ids = existing_ids | _all_case_ids
        first_live_id = (live_cases[0].get("name","").split("/")[-1] if live_cases else "?")
        logging.info(f"MTTX supplement: existing_ids={len(existing_ids)}, first_live_id={first_live_id}, start_ts={start_ts:.0f}")
        added = 0
        _skip_exists = _skip_no_ct = _skip_old = 0
        for lc in (live_cases or []):
            lc_name = lc.get("name", "")
            lc_id   = lc_name.split("/")[-1] if lc_name else str(lc.get("id", ""))
            if not lc_id or lc_id in existing_ids:
                _skip_exists += 1
                continue
            ct_str = lc.get("createTime") or lc.get("create_time")
            if not ct_str:
                _skip_no_ct += 1
                logging.info(f"MTTX supplement skip no_ct: id={lc_id} keys={list(lc.keys())[:8]}")
                continue
            try:
                s = str(ct_str).strip()
                if s.replace(".", "").replace("-", "").isdigit():
                    # Unix timestamp — REST API returns milliseconds (>1e12), history returns seconds
                    ts = float(s)
                    if ts > 1e12:
                        ts /= 1000.0
                    ct_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                else:
                    ct_dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
                ct_ts = ct_dt.timestamp()
            except Exception as _pe:
                _skip_no_ct += 1
                logging.info(f"MTTX supplement parse fail id={lc_id} ct_str={ct_str!r} err={_pe}")
                continue
            if ct_ts < start_ts or ct_ts > now_ts:  # respect the requested date range
                _skip_old += 1
                continue
            display   = lc.get("displayName") or lc_id
            _lc_title = lc.get("title") or lc.get("description") or ""
            if _is_excluded({"case_display": display, "rule_name": _lc_title}):
                continue
            close_str = lc.get("closeTime") or lc.get("close_time")
            close_dt  = None
            if close_str:
                try:
                    close_dt = datetime.fromisoformat(close_str.replace("Z", "+00:00"))
                except Exception:
                    pass
            _api_state = (lc.get("status") or lc.get("state") or "").upper()
            status    = "CLOSED" if (close_dt or _api_state == "CLOSED") else "OPEN"
            mttr_case = round((close_dt.timestamp() - ct_ts) / 60, 1) if close_dt else None
            prio_raw  = (lc.get("priority") or "PRIORITY_MEDIUM").upper()
            assignee_obj = lc.get("assignee") or {}
            assigned_to  = ""
            if isinstance(assignee_obj, dict):
                assigned_to = (assignee_obj.get("user") or assignee_obj.get("group") or "")

            # MTTD: if UDM detection data (mttd_map) exists, compute it like the main path.
            # Brand-new cases may not be in UDM yet → stays None, a later run fills it in.
            _md_s   = mttd_map.get(lc_id, {})
            _mttd_s = None
            _tc_s   = _md_s.get("created_time") or ct_ts
            if _tc_s:
                try:
                    _c_s = float(_tc_s)
                    _cands = [_md_s.get("window_start_ts"), _md_s.get("raw_event_ts"),
                              _md_s.get("detection_time_ts"), _md_s.get("alert_created_ts"),
                              (str(case_event_ts_map[lc_id]) if lc_id in case_event_ts_map else None)]
                    for _er in _cands:
                        if not _er:
                            continue
                        _e_s = float(_er)
                        if _e_s > 946684800 and 0 < (_c_s - _e_s) <= 90 * 86400:
                            _mttd_s = round((_c_s - _e_s) / 60, 1)
                            break
                except Exception:
                    pass

            rows.append({
                "alert_id": lc_id, "case_id": lc_id,
                "case_display": display, "rule_name": "Unknown Rule", "rule_id": "",
                "status": status, "priority": prio_raw, "verdict": "",
                "case_stage": "CLOSED" if close_dt else "OPEN", "case_close_reason": "",
                "resolution_type": "manual" if (close_dt and not assigned_to) else ("open" if not close_dt else "manual"),
                "det_time": ct_dt.isoformat(), "event_time": None,
                "mttd_min": _mttd_s, "mtta_min": None, "mttr_case_min": mttr_case,
                "mttp_min": None, "pb_handling_min": None, "human_handling_min": None,
                "assigned_to": assigned_to, "has_pb": False, "pb_pre_close": False,
                "has_human": bool(assigned_to),
                "assignment_chain": [{"assignee": assigned_to, "type": "human"}] if assigned_to else [],
                "alert_names": [], "timeline": [],
            })
            added += 1
        logging.info(f"MTTX list_cases supplement: {len(live_cases or [])} live, added={added}, skip_exists={_skip_exists}, skip_no_ct={_skip_no_ct}, skip_old={_skip_old}")

        # ── Sync status: mark OPEN cases that are confirmed CLOSED by live API ──
        # SAFE approach: only mark CLOSED with POSITIVE CONFIRMATION.
        # Never close a case just because it's absent from a list —
        # that would wrongly close cases that are older than the page window.
        #
        # Source 1: closeTime/status field in the 1000 unfiltered recent cases above.
        # Source 2: 1000 most recently CLOSED cases from the REST API.

        _live_closed: set[str] = set()

        # Source 1: confirmed-closed from already-fetched unfiltered supplement
        for _lc2 in (live_cases or []):
            _ln2  = _lc2.get("name", "")
            _lid2 = _ln2.split("/")[-1] if _ln2 else str(_lc2.get("id", ""))
            if not _lid2:
                continue
            _cs2 = _lc2.get("closeTime") or _lc2.get("close_time")
            _st2 = (_lc2.get("status") or _lc2.get("state") or "").upper()
            if _cs2 or _st2 == "CLOSED":
                _live_closed.add(_lid2)

        # Source 2: 1000 most recently closed cases (catches June cases closed in July)
        try:
            _params_closed = {"filter": 'status="CLOSED"', "orderBy": "closeTime desc", "pageSize": 1000}
            _r_closed = chronicle._session.get(_url, params=_params_closed)
            _r_closed.raise_for_status()
            _closed_now = _r_closed.json().get("cases") or []
            for _cc in _closed_now:
                _cn  = _cc.get("name", "")
                _cid = _cn.split("/")[-1] if _cn else str(_cc.get("id", ""))
                if _cid:
                    _live_closed.add(_cid)
            logging.info(f"MTTX status sync: {len(_live_closed)} confirmed-closed IDs (supplement + recently-closed API)")
        except Exception as _sse:
            logging.warning(f"MTTX status sync (closed-list REST) failed (non-fatal): {_sse}")

        # Apply: close OPEN history-query rows only when positively confirmed CLOSED
        _status_synced = 0
        for row in rows:
            rid = row.get("case_id") or row.get("alert_id")
            if not rid or rid not in existing_ids or row.get("status") != "OPEN":
                continue
            if rid in _live_closed:
                row["status"]          = "CLOSED"
                row["case_stage"]      = "CLOSED"
                row["resolution_type"] = row.get("resolution_type") or "manual"
                _status_synced += 1
        logging.info(f"MTTX status sync: {_status_synced} cases OPEN→CLOSED (positive confirmation only)")
    except Exception as _lce:
        logging.warning(f"MTTX list_cases supplement failed (non-fatal): {_lce}")

    # ── Gap-period close detection ────────────────────────────────────────────────
    # For historical periods (e.g. June viewed in July): some cases were OPEN at
    # period-end but were closed AFTER the period. The main history query can't see
    # those close events. Solution: query case_history for CLOSE_CASE events in the
    # gap [period_end → now] and mark matching OPEN rows as CLOSED.
    #
    # This is more reliable than the REST API "recently closed" list because it runs
    # a proper Chronicle query with adaptive chunking — no 1000-row page limits.
    if start_time and end_time:
        _gap_start = end_time
        _gap_end   = datetime.now(timezone.utc)
        _gap_days  = (_gap_end - _gap_start).days
        if _gap_days > 0:
            try:
                logging.info(f"MTTX gap-close: querying {_gap_days}d gap ({_gap_start.date()}→{_gap_end.date()}) for post-period CLOSE_CASE events")
                if _gap_days > 7:
                    _gap_rows = _query_chunked(MTTX_QUERY_HISTORY, _gap_start, _gap_end,
                                               row_limit=10000, chunk_days=7)
                else:
                    _gap_ivl  = {"time_window": {
                        "start_time": _gap_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "end_time":   _gap_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }}
                    _gap_rows = _dq_to_rows(
                        chronicle.execute_dashboard_query(query=MTTX_QUERY_HISTORY, interval=_gap_ivl)
                    )

                _closed_in_gap: set[str] = set()
                for _gr in _gap_rows:
                    if str(_gr.get("case_history_case_activity") or "") == "CLOSE_CASE":
                        _gcid = str(_gr.get("case_history_case_id") or "")
                        if _gcid:
                            _closed_in_gap.add(_gcid)
                logging.info(f"MTTX gap-close: {len(_closed_in_gap)} cases with CLOSE_CASE in gap period")

                _gap_synced = 0
                for row in rows:
                    rid = row.get("case_id") or row.get("alert_id")
                    if not rid or row.get("status") != "OPEN":
                        continue
                    if rid in _closed_in_gap:
                        row["status"]          = "CLOSED"
                        row["case_stage"]      = "CLOSED"
                        row["resolution_type"] = row.get("resolution_type") or "manual"
                        _gap_synced += 1
                logging.info(f"MTTX gap-close: {_gap_synced} cases updated OPEN→CLOSED from gap query")
            except Exception as _ge:
                logging.warning(f"MTTX gap-close query failed (non-fatal): {_ge}")

    # Chronicle SOAR REST API does not expose a comments/activities sub-resource
    # (all sub-paths return 404). pb_names is left empty; frontend shows
    # "🤖 SOAR Automation" whenever has_pb=True.
    for row in rows:
        row["pb_names"] = []

    # ── Log type distribution (dashboard query, same pattern as monitor.html) ────
    log_types = []
    try:
        _lt_raw = chronicle.execute_dashboard_query(query=MTTX_QUERY_LOG_TYPES, interval=interval)
        _lt_rows = _dq_to_rows(_lt_raw)
        log_types = [
            {"log_type": r["log_type"], "count": int(r.get("count") or 0)}
            for r in _lt_rows if r.get("log_type")
        ]
        logging.info(f"MTTX: log_types = {[(lt['log_type'], lt['count']) for lt in log_types[:5]]}")
    except Exception as _e:
        logging.warning(f"MTTX: log_types query failed: {_e}")

    # ── Alert-type distribution (from mttd_map, filtered rows only) ─────────────
    from collections import Counter as _Counter
    _at_ctr = _Counter()
    for _r in rows:
        _cid = _r.get("case_id") or _r.get("alert_id")
        _atypes = mttd_map.get(_cid, {}).get("alert_types") or ["UNKNOWN"]
        for _at in _atypes:
            _at_ctr[_at or "UNKNOWN"] += 1
    alert_type_distribution = [
        {"type": t, "count": c}
        for t, c in sorted(_at_ctr.items(), key=lambda x: -x[1])
    ]

    summary = _mttx_aggregate(rows)
    # Alert count via get_alerts (baselineAlertsCount = unique alert detections)
    try:
        _alert_resp = chronicle.get_alerts(
            start_time=start, end_time=now,
            baseline_query=None, snapshot_query=None,
            max_alerts=1, max_attempts=10, poll_interval=0.5,
        )
        _total_det = _alert_resp.get("baselineAlertsCount") or _alert_resp.get("filteredAlertsCount")
        if _total_det:
            summary["total_alert_detections"] = int(_total_det)
            logging.info(f"MTTX: total_alert_detections={_total_det} (get_alerts)")
    except Exception as _ae:
        logging.warning(f"MTTX: get_alerts count failed: {_ae}")
    return {
        "tenant_name": tenant.name,
        "days":        days,
        "start_time":  start.isoformat(),
        "end_time":    now.isoformat(),
        "is_demo":              False,
        "summary":              summary,
        "log_types":            log_types,
        "alert_type_distribution": alert_type_distribution,
        "alerts":               sorted(rows, key=lambda r: r["det_time"], reverse=True),
    }


# ── MTTX Routes ───────────────────────────────────────────────────────────────
@api_router.get("/mttx/latest/{tenant_id}")
def mttx_latest(tenant_id: int, db: Session = Depends(get_db)):
    run = db.query(MttxRun).filter(MttxRun.tenant_id == tenant_id).order_by(MttxRun.id.desc()).first()
    if not run or not run.result_json:
        raise HTTPException(status_code=404, detail="No previous run found")
    data = json.loads(run.result_json)
    data["run_id"] = run.id
    data["run_at"] = run.run_at
    data["is_cached"] = True
    return data


@api_router.get("/mttx/cache/clear-months")
def mttx_clear_month_cache(db: Session = Depends(get_db)):
    """Delete all month-range cache entries so precache re-fetches with latest code."""
    try:
        from sqlalchemy import text as _text
        result = db.execute(_text("DELETE FROM mttx_runs WHERE start_date IS NOT NULL AND end_date IS NOT NULL"))
        db.commit()
        deleted = result.rowcount
        logging.info(f"MTTX cache: cleared {deleted} month cache entries (manual)")
        return {"deleted": deleted, "message": "Precache will rebuild in ~30s"}
    except Exception as e:
        logging.error(f"MTTX cache clear error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/mttx/cached/{tenant_id}")
def mttx_cached(
    tenant_id: int,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    max_age_min: int = 60,
    db: Session = Depends(get_db),
):
    """Return a pre-cached run matching exact date range, if fresh enough.
    For month-range requests (start_date + end_date supplied) this enables
    instant page loads when the background pre-cacher has already done the work.
    max_age_min: reject cache entries older than this many minutes (default 60).
    """
    q = db.query(MttxRun).filter(MttxRun.tenant_id == tenant_id)
    if start_date and end_date:
        q = q.filter(MttxRun.start_date == start_date, MttxRun.end_date == end_date)
    else:
        q = q.filter(MttxRun.start_date.is_(None), MttxRun.end_date.is_(None))
    run = q.order_by(MttxRun.id.desc()).first()
    if not run or not run.result_json:
        raise HTTPException(status_code=404, detail="No cached run found")
    try:
        run_age_sec = (datetime.now(timezone.utc) - datetime.fromisoformat(run.run_at)).total_seconds()
    except Exception:
        run_age_sec = 9999999
    if run_age_sec > max_age_min * 60:
        raise HTTPException(status_code=404, detail=f"Cache too old ({int(run_age_sec/60)}m > {max_age_min}m)")
    data = json.loads(run.result_json)
    data["run_id"]   = run.id
    data["run_at"]   = run.run_at
    data["is_cached"] = True
    data["cache_age_min"] = round(run_age_sec / 60, 1)
    return data


@api_router.get("/mttx/log-types/{tenant_id}")
def mttx_log_types(tenant_id: int, days: int = 7, start_date: Optional[str] = None, end_date: Optional[str] = None, db: Session = Depends(get_db)):
    """Fetch log type distribution via execute_dashboard_query (same as monitor.html data sources)."""
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant or not SECOPS_SDK_AVAILABLE:
        return {"log_types": []}
    try:
        client = _secops_client()
        chronicle = client.chronicle(customer_id=tenant.guid,
                                     project_id=tenant.gcp_project_id,
                                     region=tenant.region)
        if start_date and end_date:
            _s = datetime.fromisoformat(start_date).replace(tzinfo=timezone.utc)
            _e = (datetime.fromisoformat(end_date).replace(tzinfo=timezone.utc)
                  + timedelta(days=1) - timedelta(seconds=1))
            interval = {"time_window": {"start_time": _s.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                        "end_time":   _e.strftime("%Y-%m-%dT%H:%M:%SZ")}}
        else:
            interval = {"relativeTime": {"timeUnit": "DAY", "startTimeVal": str(days)}}
        _lt_raw = chronicle.execute_dashboard_query(query=MTTX_QUERY_LOG_TYPES, interval=interval)
        _lt_rows = _dq_to_rows(_lt_raw)
        log_types = [
            {"log_type": r["log_type"], "count": int(r.get("count") or 0)}
            for r in _lt_rows if r.get("log_type")
        ]
        # Total ingested GB via ingestion entity query
        total_gb = 0.0
        try:
            _ig_raw  = chronicle.execute_dashboard_query(query=MTTX_QUERY_INGESTION_GB, interval=interval)
            _ig_rows = _dq_to_rows(_ig_raw)
            if _ig_rows:
                total_gb = float(_ig_rows[0].get("total_gb") or 0)
        except Exception as _ige:
            logging.warning(f"log-types ingestion GB query failed (non-fatal): {_ige}")
        logging.info(f"log-types endpoint: {len(log_types)} types, {total_gb} GB for tenant {tenant.guid}")
        return {"log_types": log_types, "total_ingested_gb": total_gb}
    except Exception as e:
        logging.warning(f"log-types endpoint failed: {e}")
        return {"log_types": []}


@api_router.get("/mttx/alert-count/{tenant_id}")
def mttx_alert_count(tenant_id: int, days: int = 7, start_date: Optional[str] = None, end_date: Optional[str] = None, db: Session = Depends(get_db)):
    """Count total alerts via search_rule_alerts (legacySearchRulesAlerts)."""
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant or not SECOPS_SDK_AVAILABLE:
        return {"total_detections": 0}
    try:
        client = _secops_client()
        chronicle = client.chronicle(customer_id=tenant.guid,
                                     project_id=tenant.gcp_project_id,
                                     region=tenant.region)
        if start_date and end_date:
            start = datetime.fromisoformat(start_date).replace(tzinfo=timezone.utc)
            now   = (datetime.fromisoformat(end_date).replace(tzinfo=timezone.utc)
                     + timedelta(days=1) - timedelta(seconds=1))
        else:
            now   = datetime.now(timezone.utc)
            start = now - timedelta(days=days)
        resp = chronicle.search_rule_alerts(start_time=start, end_time=now)
        rule_alerts = resp.get("ruleAlerts") or []
        total = sum(len(ra.get("alerts") or []) for ra in rule_alerts)
        too_many = resp.get("tooManyAlerts", False)
        logging.info(f"alert-count: {total} alerts (tooMany={too_many}) for tenant {tenant.guid}")
        return {"total_detections": total, "too_many": too_many}
    except Exception as e:
        logging.warning(f"alert-count endpoint failed: {e}")
        return {"total_detections": 0}


@api_router.get("/mttx/history")
def mttx_list_history(db: Session = Depends(get_db)):
    runs = db.query(MttxRun).order_by(MttxRun.id.desc()).limit(50).all()
    out = []
    for r in runs:
        result = json.loads(r.result_json) if r.result_json else {}
        s = result.get("summary", {})
        out.append({
            "id": r.id, "tenant_id": r.tenant_id, "days": r.days,
            "run_at": r.run_at, "is_demo": r.is_demo,
            "total_alerts": s.get("total_alerts", 0),
            "avg_mttd": s.get("avg_mttd"), "avg_mtta": s.get("avg_mtta"),
            "avg_mttp": s.get("avg_mttp"),
            "automation_rate": s.get("automation_rate"),
            "escalation_rate": s.get("escalation_rate"),
        })
    return out


@api_router.get("/mttx/history/{run_id}")
def mttx_get_history(run_id: int, db: Session = Depends(get_db)):
    run = db.query(MttxRun).filter(MttxRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return json.loads(run.result_json)


@api_router.get("/mttx/debug/pb-raw/{tenant_id}")
def mttx_debug_pb_raw(tenant_id: int, days: int = 30, db: Session = Depends(get_db)):
    """
    Debug endpoint — shows raw case_history.name / case_activity values
    returned by MTTX_QUERY_PB_COMMENTS so we can verify what Chronicle sends.
    Access: GET /api/mttx/debug/pb-raw/{tenant_id}?days=30
    """
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    if not SECOPS_SDK_AVAILABLE:
        raise HTTPException(status_code=503, detail="SecOps SDK not available")

    client    = _secops_client()
    chronicle = client.chronicle(customer_id=tenant.guid,
                                 project_id=tenant.gcp_project_id,
                                 region=tenant.region)
    interval  = {"relativeTime": {"timeUnit": "DAY", "startTimeVal": str(days)}}
    try:
        raw  = chronicle.execute_dashboard_query(query=MTTX_QUERY_PB_COMMENTS, interval=interval)
        rows = _dq_to_rows(raw)
    except Exception as e:
        return {"error": str(e), "row_count": 0, "samples": []}

    samples = []
    for pr in rows[:30]:
        cid    = str(pr.get("case_id") or "")
        acts   = pr.get("activities") or []
        descs  = pr.get("pb_descs")   or []
        if isinstance(acts,  str): acts  = [acts]
        if isinstance(descs, str): descs = [descs]
        samples.append({
            "case_id":    cid,
            "activities": [str(a)[:200] for a in acts],
            "pb_descs":   [str(d)[:200] for d in descs],
        })

    # Show only rows that have something playbook-related
    soar_samples = [s for s in samples if any(
        "playbook" in v.lower() or "soar" in v.lower()
        for v in s["activities"] + s["pb_descs"]
    )]

    return {
        "row_count":    len(rows),
        "soar_matches": len(soar_samples),
        "all_samples":  samples[:10],     # first 10 rows regardless
        "soar_samples": soar_samples[:10], # first 10 rows with SOAR/playbook content
    }


@api_router.get("/mttx/debug/pb-comments/{tenant_id}")
def mttx_debug_pb_comments(
    tenant_id: int,
    case_id: str = "",
    db: Session = Depends(get_db),
):
    """
    Debug: call Chronicle SOAR comments REST API for a specific case and return raw response.
    Also auto-picks a recent SOAR case if case_id is omitted.

    Access: GET /api/mttx/debug/pb-comments/{tenant_id}?case_id=453066
    """
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    if not SECOPS_SDK_AVAILABLE:
        raise HTTPException(status_code=503, detail="SecOps SDK not available")

    client    = _secops_client()
    chronicle = client.chronicle(
        customer_id=tenant.guid,
        project_id=tenant.gcp_project_id,
        region=tenant.region,
    )

    inst     = chronicle.instance_id
    base_url = f"https://{tenant.region}-chronicle.googleapis.com/v1/{inst}/cases"

    # If no case_id given, auto-pick the most recent SOAR-assigned case
    if not case_id:
        try:
            _r = chronicle._session.get(
                base_url,
                params={"orderBy": "createTime desc", "pageSize": 50},
                timeout=15,
            )
            _r.raise_for_status()
            _cases = _r.json().get("cases", [])
            # pick first one that has an assignee containing "soar" or "playbook"
            for _c in _cases:
                _asgn = str(_c.get("assignee") or "").lower()
                if "soar" in _asgn or "playbook" in _asgn:
                    case_id = _c.get("name", "").split("/")[-1]
                    break
            if not case_id and _cases:
                case_id = _cases[0].get("name", "").split("/")[-1]
        except Exception as _e:
            return {"error": f"Could not auto-pick case: {_e}"}

    if not case_id:
        return {"error": "No case_id found. Pass ?case_id=XXXXX"}

    # Try multiple sub-resource paths to find where comments/activities live
    _paths_to_try = [
        f"{base_url}/{case_id}",
        f"{base_url}/{case_id}/comments",
        f"{base_url}/{case_id}/alerts",
        f"{base_url}/{case_id}/activities",
        f"{base_url}/{case_id}/history",
        f"{base_url}/{case_id}/timeline",
    ]
    results = {}
    for _url in _paths_to_try:
        try:
            _r = chronicle._session.get(_url, timeout=15)
            try:
                _body = _r.json()
                # Truncate large responses — we only need the shape
                _body_str = str(_body)
                if len(_body_str) > 3000:
                    _body = {"__truncated__": True, "preview": _body_str[:3000]}
            except Exception:
                _body = _r.text[:1000]
            results[_url.split(f"cases/{case_id}")[-1] or "/"] = {
                "status": _r.status_code,
                "body":   _body,
            }
        except Exception as _e:
            results[_url.split(f"cases/{case_id}")[-1] or "/"] = {"error": str(_e)}

    return {
        "case_id":   case_id,
        "base_url":  base_url,
        "results":   results,
    }


@api_router.post("/mttx/run")
def mttx_run(req: MttxRunRequest, db: Session = Depends(get_db)):
    tenant = db.query(Tenant).filter(Tenant.id == req.tenant_id).first() if req.tenant_id else None

    if not SECOPS_SDK_AVAILABLE:
        raise HTTPException(status_code=503, detail="SecOps SDK not available")
    if tenant is None:
        raise HTTPException(status_code=400, detail="Tenant not found")

    start_time: Optional[datetime] = None
    end_time:   Optional[datetime] = None
    effective_days = req.days
    if req.start_date and req.end_date:
        start_time = datetime.fromisoformat(req.start_date).replace(tzinfo=timezone.utc)
        end_time   = (datetime.fromisoformat(req.end_date).replace(tzinfo=timezone.utc)
                      + timedelta(days=1) - timedelta(seconds=1))
        effective_days = (end_time - start_time).days + 1

    try:
        result = _mttx_live_run(tenant, effective_days, start_time, end_time)
    except Exception as e:
        import traceback
        logging.error(f"MTTX live query failed:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

    now_str = datetime.now(timezone.utc).isoformat()
    run = MttxRun(
        tenant_id=req.tenant_id or 0,
        days=req.days,
        start_date=req.start_date or None,
        end_date=req.end_date or None,
        run_at=now_str,
        result_json=json.dumps(result),
        is_demo=result.get("is_demo", True),
    )
    db.add(run); db.commit(); db.refresh(run)
    result["run_id"] = run.id
    result["run_at"] = now_str
    return result

# ══════════════════════════════════════════════════════════════════════════════
# SINGLE-PASSWORD COOKIE GATE — protects all human-facing pages (works standalone; nginx optional).
# Sign in once → signed HttpOnly cookie (default 12h) → grants access to all protected pages.
# /auth, /version and /favicon are exempt so login and assets don't break.
# Config: env MTTX_PASSWORD (login password), optional MTTX_SECRET, MTTX_SECURE, MTTX_TTL_HOURS.
# ══════════════════════════════════════════════════════════════════════════════
import hmac as _hmac, hashlib as _hashlib
from fastapi import Request as _Request
from fastapi.responses import HTMLResponse as _HTMLResponse, RedirectResponse as _RedirectResponse, Response as _FAResponse

_GATE_TTL    = int(os.environ.get("MTTX_TTL_HOURS", "12")) * 3600
_GATE_COOKIE = "mttx_gate"

def _hash_pw(pw: str) -> str:
    return _hashlib.sha256(("mttx::" + pw).encode()).hexdigest()

def _set_setting(key: str, value: str):
    """Upsert an app_settings key (used for auth config)."""
    _db = SessionLocal()
    try:
        row = _db.query(AppSetting).filter(AppSetting.key == key).first()
        if row:
            row.value = value
        else:
            _db.add(AppSetting(key=key, value=value))
        _db.commit()
    finally:
        _db.close()

def _auth_hash() -> str:
    """Current password hash. Env MTTX_PASSWORD overrides the DB when set; empty = auth disabled."""
    env_pw = os.environ.get("MTTX_PASSWORD", "")
    if env_pw:
        return _hash_pw(env_pw)
    return _get_setting("auth_password_hash", "")

def _auth_secret() -> str:
    """Cookie-signing secret. Derived from env when MTTX_PASSWORD is set, else stored in the DB."""
    env_pw = os.environ.get("MTTX_PASSWORD", "")
    if env_pw:
        return os.environ.get("MTTX_SECRET", "") or _hashlib.sha256(("mttx-gate::" + env_pw).encode()).hexdigest()
    return _get_setting("auth_secret", "")

def _gate_enabled() -> bool:
    return bool(_auth_hash() and _auth_secret())

def _gate_sign(exp: int) -> str:
    sig = _hmac.new(_auth_secret().encode(), str(exp).encode(), _hashlib.sha256).hexdigest()
    return f"{exp}.{sig}"

def _gate_valid(token: str) -> bool:
    try:
        secret = _auth_secret()
        if not secret:
            return False
        exp_s, sig = token.split(".", 1)
        exp = int(exp_s)
        if exp < int(time.time()):
            return False
        good = _hmac.new(secret.encode(), str(exp).encode(), _hashlib.sha256).hexdigest()
        return _hmac.compare_digest(sig, good)
    except Exception:
        return False

def _gate_safe_next(nxt: str) -> str:
    if not nxt or not nxt.startswith("/") or nxt.startswith("//") or nxt.startswith("/auth"):
        return "/"
    return nxt

_GATE_LOGIN_HTML = """<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Sign in</title></head>
<body style="margin:0;font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#0b0f1e;color:#e7ebf3;display:flex;align-items:center;justify-content:center;min-height:100vh;">
<form method="post" action="/auth/login" style="background:#111a2e;padding:36px;border-radius:16px;border:1px solid #22304e;width:320px;text-align:center;">
<div style="font-size:44px;">&#128274;</div>
<div style="font-size:20px;font-weight:800;margin:10px 0 4px;">MTTX Dashboard</div>
<div style="font-size:13px;color:#8b97b0;margin-bottom:18px;">Sign in to continue</div>
__ERR__
<input type="hidden" name="next" value="__NEXT__">
<input type="password" name="password" placeholder="Password" autofocus required style="width:100%;box-sizing:border-box;padding:12px;border-radius:9px;border:1px solid #2a3a5a;background:#0b0f1e;color:#e7ebf3;font-size:15px;margin-bottom:12px;">
<button type="submit" style="width:100%;padding:12px;border:none;border-radius:9px;background:#FFE800;color:#0b0f1e;font-size:15px;font-weight:800;cursor:pointer;">Sign in</button>
</form></body></html>"""

@app.get("/auth/login")
def gate_login_page(next: str = "/"):
    html = _GATE_LOGIN_HTML.replace("__ERR__", "").replace("__NEXT__", _gate_safe_next(next).replace('"', '&quot;'))
    return _HTMLResponse(html)

@app.post("/auth/login")
async def gate_login(request: _Request):
    # Parse the urlencoded form manually so we don't depend on python-multipart.
    raw = (await request.body()).decode("utf-8", "ignore")
    data = urllib.parse.parse_qs(raw, keep_blank_values=True)
    pw = data.get("password", [""])[0]
    nxt = _gate_safe_next(data.get("next", ["/"])[0])
    if _gate_enabled() and _hmac.compare_digest(_hash_pw(pw), _auth_hash()):
        token = _gate_sign(int(time.time()) + _GATE_TTL)
        resp = _RedirectResponse(url=nxt, status_code=302)
        _secure = os.environ.get("MTTX_SECURE", "0") == "1"
        resp.set_cookie(_GATE_COOKIE, token, max_age=_GATE_TTL, httponly=True, samesite="lax", path="/", secure=_secure)
        return resp
    err = "<div style='color:#f87171;font-size:13px;margin-bottom:12px;'>Wrong password</div>"
    html = _GATE_LOGIN_HTML.replace("__ERR__", err).replace("__NEXT__", nxt.replace('"', '&quot;'))
    return _HTMLResponse(html, status_code=401)

@app.get("/auth/verify")
def gate_verify(request: _Request):
    if _gate_valid(request.cookies.get(_GATE_COOKIE, "")):
        return _FAResponse(status_code=200)
    return _FAResponse(status_code=401)

@app.get("/auth/logout")
def gate_logout():
    resp = _RedirectResponse(url="/auth/login", status_code=302)
    resp.delete_cookie(_GATE_COOKIE, path="/")
    return resp


# ── Configurable case filter (exclusions) — CRUD ─────────────────────────────
class ExclusionIn(BaseModel):
    keyword: str
    note: Optional[str] = None

@api_router.get("/exclusions")
def list_exclusions(db: Session = Depends(get_db)):
    rows = db.query(CaseExclusion).order_by(CaseExclusion.id.asc()).all()
    return [{"id": r.id, "keyword": r.keyword, "note": r.note, "created_at": r.created_at} for r in rows]

@api_router.post("/exclusions", status_code=201)
def add_exclusion(body: ExclusionIn, db: Session = Depends(get_db)):
    kw = (body.keyword or "").strip()
    if not kw:
        raise HTTPException(400, "keyword required")
    if db.query(CaseExclusion).filter(CaseExclusion.keyword == kw).first():
        raise HTTPException(409, "already exists")
    row = CaseExclusion(keyword=kw, note=(body.note or None))
    db.add(row); db.commit(); db.refresh(row)
    return {"id": row.id, "keyword": row.keyword, "note": row.note, "created_at": row.created_at}

@api_router.delete("/exclusions/{exc_id}", status_code=204)
def del_exclusion(exc_id: int, db: Session = Depends(get_db)):
    row = db.query(CaseExclusion).filter(CaseExclusion.id == exc_id).first()
    if row:
        db.delete(row); db.commit()
    return


# ── Branding (logo) — configurable, no baked-in organization assets ───────────
class BrandingIn(BaseModel):
    logo: Optional[str] = None   # data URL (e.g. data:image/png;base64,...) or an https URL

@api_router.get("/branding")
def get_branding(db: Session = Depends(get_db)):
    row = db.query(AppSetting).filter(AppSetting.key == "logo").first()
    return {"logo": (row.value if row and row.value else "")}

@api_router.put("/branding")
def set_branding(body: BrandingIn, db: Session = Depends(get_db)):
    val = (body.logo or "").strip()
    if val and not (val.startswith("data:image/") or val.startswith("https://")):
        raise HTTPException(400, "logo must be a data:image/... URL or an https:// URL")
    if len(val) > 3_000_000:
        raise HTTPException(413, "logo too large (max ~3 MB)")
    row = db.query(AppSetting).filter(AppSetting.key == "logo").first()
    if row:
        row.value = val
    else:
        db.add(AppSetting(key="logo", value=val))
    db.commit()
    return {"logo": val}

@api_router.delete("/branding", status_code=204)
def del_branding(db: Session = Depends(get_db)):
    row = db.query(AppSetting).filter(AppSetting.key == "logo").first()
    if row:
        db.delete(row); db.commit()
    return


# ── Access / login password — configurable from Settings (stored hashed in the DB) ──
class PasswordIn(BaseModel):
    password: str
    env_locked: Optional[bool] = None   # informational only

@api_router.get("/auth/config")
def auth_config():
    """Whether login is enabled, and whether it's fixed by the MTTX_PASSWORD env var."""
    return {"enabled": _gate_enabled(), "env_locked": bool(os.environ.get("MTTX_PASSWORD", ""))}

@api_router.put("/auth/password")
def set_password(body: PasswordIn):
    if os.environ.get("MTTX_PASSWORD", ""):
        raise HTTPException(409, "Password is fixed by the MTTX_PASSWORD environment variable")
    pw = (body.password or "")
    if len(pw) < 4:
        raise HTTPException(400, "Password must be at least 4 characters")
    _set_setting("auth_password_hash", _hash_pw(pw))
    _set_setting("auth_secret", secrets.token_hex(32))   # new secret invalidates old cookies
    return {"enabled": True}

@api_router.delete("/auth/password", status_code=204)
def disable_password():
    if os.environ.get("MTTX_PASSWORD", ""):
        raise HTTPException(409, "Password is fixed by the MTTX_PASSWORD environment variable")
    _set_setting("auth_password_hash", "")
    _set_setting("auth_secret", "")
    return


# ── Google SecOps service account — uploadable from Settings ──────────────────
class CredentialsIn(BaseModel):
    content: str   # raw service-account JSON text

@api_router.get("/credentials")
def get_credentials():
    """Non-secret status of the configured service account (never returns the private key)."""
    if not os.path.exists(_SA_PATH):
        return {"configured": False}
    try:
        with open(_SA_PATH, "r") as f:
            data = json.load(f)
        return {"configured": True,
                "client_email": data.get("client_email"),
                "project_id": data.get("project_id"),
                "sdk_available": SECOPS_SDK_AVAILABLE}
    except Exception:
        return {"configured": True, "client_email": None, "project_id": None, "sdk_available": SECOPS_SDK_AVAILABLE}

@api_router.put("/credentials")
def set_credentials(body: CredentialsIn):
    try:
        data = json.loads(body.content)
    except Exception:
        raise HTTPException(400, "Not valid JSON")
    if data.get("type") != "service_account" or not data.get("client_email") or not data.get("private_key"):
        raise HTTPException(400, "Not a Google service-account key (need type=service_account, client_email, private_key)")
    with open(_SA_PATH, "w") as f:
        json.dump(data, f)
    try:
        os.chmod(_SA_PATH, 0o600)
    except Exception:
        pass
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = _SA_PATH
    return {"configured": True, "client_email": data.get("client_email"), "project_id": data.get("project_id")}

@api_router.delete("/credentials", status_code=204)
def del_credentials():
    try:
        if os.path.exists(_SA_PATH):
            os.remove(_SA_PATH)
    except Exception:
        pass
    return


# ── In-app login enforcement (protected even without nginx) ───────────────────
@app.middleware("http")
async def _require_gate(request: _Request, call_next):
    # Open mode when no password is set (works out of the box; locks once a password is set in Settings)
    if not _gate_enabled():
        return await call_next(request)
    p = request.url.path
    if p.startswith("/auth") or p == "/version" or p.startswith("/favicon"):
        return await call_next(request)
    if _gate_valid(request.cookies.get(_GATE_COOKIE, "")):
        return await call_next(request)
    if "text/html" in (request.headers.get("accept") or ""):
        return _RedirectResponse(url=f"/auth/login?next={p}", status_code=302)
    return _FAResponse(content='{"detail":"Unauthorized"}', status_code=401, media_type="application/json")


app.include_router(api_router, prefix="/api")

# ── No-cache ASGI middleware for HTML files ───────────────────────────────────
# Must operate at raw ASGI level so we can strip If-None-Match / If-Modified-Since
# BEFORE StaticFiles sees them (otherwise StaticFiles returns 304 and we can't
# intercept the cached response that the browser uses).
_HTML_EXTS = frozenset({b".html", b".htm"})
_STRIP_REQ  = frozenset({b"if-none-match", b"if-modified-since"})
_NO_CACHE   = [(b"cache-control", b"no-store, no-cache, must-revalidate, max-age=0"),
               (b"pragma",        b"no-cache"),
               (b"expires",       b"0")]

class NoCacheHtmlMiddleware:
    """Raw ASGI middleware — strips conditional request headers for HTML requests
    so StaticFiles always returns 200 (never 304), then adds no-cache response
    headers so the browser won't cache the file at all."""

    def __init__(self, app_inner):
        self.app = app_inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        import os as _os
        ext = _os.path.splitext(path)[1].lower().encode()
        # Only intercept real HTML files and the root path — NOT /api/* paths
        is_html = (ext in _HTML_EXTS) or (path in ("/", "") and not path.startswith("/api"))

        if not is_html:
            await self.app(scope, receive, send)
            return

        # Strip conditional request headers to force a fresh 200 response
        new_headers = [
            (k, v) for k, v in scope.get("headers", [])
            if k.lower() not in _STRIP_REQ
        ]
        scope = {**scope, "headers": new_headers}

        async def send_no_cache(message):
            if message["type"] == "http.response.start":
                # Add no-cache headers; remove any existing cache-control
                existing = [(k, v) for k, v in message.get("headers", [])
                            if k.lower() not in (b"cache-control", b"pragma", b"expires")]
                message = {**message, "headers": existing + _NO_CACHE}
            await send(message)

        await self.app(scope, receive, send_no_cache)

app.add_middleware(NoCacheHtmlMiddleware)

frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8011)