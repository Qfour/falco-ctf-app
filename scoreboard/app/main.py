"""falco-ctf scoreboard.

Subscribes to falcosidekick's `customWebhook` output, attributes events to
users via `k8s.ns.name == ctf-<username>`, and supports two challenge types:

  - trigger: solved when an `expectedRules` rule fires from the user's pod
  - evade:   solved when the user POSTs the correct flag AND no
             `forbiddenRules` rule fired in the last `windowSeconds` seconds

State persistence:
  - SOLVED (user×challenge -> ts)  — SQLite at SCOREBOARD_DB
  - EVENTS_PER_USER (user -> count) — SQLite at SCOREBOARD_DB
  - RULE_FIRES (user -> [(rule, ts)...])  — in-memory only, bounded to last
    5 minutes per user. Pod restart loses this; the time-window check on
    evade challenges is briefly less strict until events flow again.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse


CHALLENGES_DIR = Path(os.environ.get("CHALLENGES_DIR", "/app/challenges"))
DB_PATH = Path(os.environ.get("SCOREBOARD_DB", "/var/lib/scoreboard/scoreboard.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_iso_to_unix(ts: str) -> float:
    try:
        cleaned = ts.rstrip("Z")
        if "." in cleaned:
            head, frac = cleaned.split(".", 1)
            frac = frac[:6]
            cleaned = f"{head}.{frac}"
        dt = datetime.fromisoformat(cleaned).replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0


def load_catalog() -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    if not CHALLENGES_DIR.exists():
        return catalog
    for d in sorted(CHALLENGES_DIR.iterdir()):
        rule_file = d / "falco-rule.yaml"
        if not rule_file.is_file():
            continue
        spec = yaml.safe_load(rule_file.read_text()) or {}
        cid = spec.get("challengeId") or d.name
        ctype = spec.get("type") or ("trigger" if spec.get("expectedRules") else "evade")
        catalog[cid] = {
            "type": ctype,
            "expectedRules": list(spec.get("expectedRules") or []),
            "forbiddenRules": list(spec.get("forbiddenRules") or []),
            "expectedFlag": spec.get("expectedFlag") or "",
            "windowSeconds": int(spec.get("windowSeconds") or 10),
        }
    return catalog


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _open_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS solved (
          user      TEXT NOT NULL,
          challenge TEXT NOT NULL,
          at        TEXT NOT NULL,
          PRIMARY KEY (user, challenge)
        );
        CREATE TABLE IF NOT EXISTS events_per_user (
          user  TEXT PRIMARY KEY,
          count INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    return conn


CATALOG: dict[str, dict[str, Any]] = load_catalog()

_lock = threading.Lock()
_db = _open_db()

SOLVED: dict[tuple[str, str], str] = {
    (r[0], r[1]): r[2] for r in _db.execute("SELECT user, challenge, at FROM solved")
}
EVENTS_PER_USER: dict[str, int] = defaultdict(
    int,
    {r[0]: r[1] for r in _db.execute("SELECT user, count FROM events_per_user")},
)
RULE_FIRES: dict[str, list[tuple[str, float]]] = defaultdict(list)
_RETENTION_SECONDS = 300


def _save_solved(user: str, cid: str, at: str) -> None:
    _db.execute(
        "INSERT OR IGNORE INTO solved (user, challenge, at) VALUES (?, ?, ?)",
        (user, cid, at),
    )


def _save_events(user: str, count: int) -> None:
    _db.execute(
        "INSERT INTO events_per_user (user, count) VALUES (?, ?) "
        "ON CONFLICT(user) DO UPDATE SET count = excluded.count",
        (user, count),
    )


# ---------------------------------------------------------------------------
# State view builder (shared by HTML and JSON API)
# ---------------------------------------------------------------------------

def _build_state() -> dict[str, Any]:
    with _lock:
        users = sorted(set(EVENTS_PER_USER) | {u for (u, _) in SOLVED})
        challenges = sorted(CATALOG)

        per_user_solves: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for (u, c), t in SOLVED.items():
            per_user_solves[u].append((c, t))

        # Leaderboard: solved desc, then earliest first-solve asc (first-to-solve wins ties)
        leaderboard: list[dict[str, Any]] = []
        for u in users:
            solves = per_user_solves.get(u, [])
            earliest = min((t for _, t in solves), default="9999")
            leaderboard.append({
                "user": u,
                "solved": len(solves),
                "earliest": earliest,
                "events": EVENTS_PER_USER.get(u, 0),
            })
        leaderboard.sort(key=lambda x: (-x["solved"], x["earliest"]))
        for rank, p in enumerate(leaderboard, 1):
            p["rank"] = rank

        per_chal_solvers: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for (u, c), t in SOLVED.items():
            per_chal_solvers[c].append((u, t))

        challenge_stats: list[dict[str, Any]] = []
        for cid in challenges:
            ch = CATALOG[cid]
            solvers = sorted(per_chal_solvers.get(cid, []), key=lambda x: x[1])
            challenge_stats.append({
                "id": cid,
                "type": ch["type"],
                "expectedRules": ch["expectedRules"],
                "forbiddenRules": ch["forbiddenRules"],
                "solved_count": len(solvers),
                "solvers": [s[0] for s in solvers],
                "first_solver": solvers[0][0] if solvers else None,
            })

        recent = sorted(
            [{"user": u, "challenge": c, "at": t} for (u, c), t in SOLVED.items()],
            key=lambda x: x["at"], reverse=True,
        )[:15]

        return {
            "stats": {
                "users": len(users),
                "challenges": len(challenges),
                "solves": len(SOLVED),
                "events": sum(EVENTS_PER_USER.values()),
            },
            "leaderboard": leaderboard,
            "challenges": challenge_stats,
            "recent_solves": recent,
            # Back-compat fields used by older tooling / verify scripts.
            "solved": [
                {"user": u, "challenge": c, "at": t}
                for (u, c), t in SOLVED.items()
            ],
            "events_per_user": dict(EVENTS_PER_USER),
            "now": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(title="falco-ctf scoreboard")


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {
        "ok": True,
        "challenges": list(CATALOG.keys()),
        "db": str(DB_PATH),
        "solved_loaded": len(SOLVED),
    }


@app.post("/falco/events")
async def receive(request: Request) -> JSONResponse:
    payload = await request.json()
    rule = payload.get("rule") or ""
    fields = payload.get("output_fields") or {}
    ns: str = fields.get("k8s.ns.name") or ""
    pod: str = fields.get("k8s.pod.name") or ""
    ts: str = payload.get("time") or datetime.now(timezone.utc).isoformat()

    if not ns.startswith("ctf-") or pod != "workspace":
        return JSONResponse({"ignored": True, "reason": "not a ctf workspace event"})

    user = ns.removeprefix("ctf-")
    ts_unix = _parse_iso_to_unix(ts) or datetime.now(timezone.utc).timestamp()

    with _lock:
        EVENTS_PER_USER[user] += 1
        _save_events(user, EVENTS_PER_USER[user])

        fires = RULE_FIRES[user]
        fires.append((rule, ts_unix))
        cutoff = ts_unix - _RETENTION_SECONDS
        RULE_FIRES[user] = [(r, t) for (r, t) in fires if t >= cutoff]

        for cid, ch in CATALOG.items():
            if ch["type"] == "trigger" and rule in ch["expectedRules"]:
                key = (user, cid)
                if key not in SOLVED:
                    SOLVED[key] = ts
                    _save_solved(user, cid, ts)

    return JSONResponse({"accepted": True, "user": user, "rule": rule})


@app.post("/api/challenges/{cid}/submit")
async def submit(cid: str, request: Request) -> JSONResponse:
    payload = await request.json()
    user = (payload.get("user") or "").strip()
    flag = (payload.get("flag") or "").strip()

    if cid not in CATALOG:
        raise HTTPException(status_code=404, detail=f"unknown challenge: {cid}")
    ch = CATALOG[cid]
    if ch["type"] != "evade":
        raise HTTPException(status_code=400, detail=f"{cid} is not an evade challenge")
    if not user:
        raise HTTPException(status_code=400, detail="user required")
    if flag != ch["expectedFlag"]:
        return JSONResponse({"correct": False, "reason": "flag mismatch"})

    now = datetime.now(timezone.utc).timestamp()
    cutoff = now - ch["windowSeconds"]
    with _lock:
        recent_fires = [
            (r, t) for (r, t) in RULE_FIRES.get(user, [])
            if t >= cutoff and r in ch["forbiddenRules"]
        ]
        if recent_fires:
            offending = sorted({r for (r, _) in recent_fires})
            return JSONResponse({
                "correct": True,
                "evaded": False,
                "reason": (
                    f"flag is correct, but the forbidden rule(s) {offending} fired "
                    f"in the last {ch['windowSeconds']}s for user '{user}'. "
                    f"Try again — wait {ch['windowSeconds']}s, then submit."
                ),
            })
        key = (user, cid)
        if key not in SOLVED:
            at = datetime.now(timezone.utc).isoformat()
            SOLVED[key] = at
            _save_solved(user, cid, at)
        return JSONResponse({"correct": True, "evaded": True, "solved": True, "user": user})


@app.get("/api/state")
def state() -> dict[str, Any]:
    return _build_state()


# ---------------------------------------------------------------------------
# HTML — modern dark theme, live-updated via fetch()
# ---------------------------------------------------------------------------

_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>falco-ctf · scoreboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #07090f;
    --bg-elev: #0d1119;
    --surface: #131826;
    --surface-2: #1a2030;
    --border: #232a3d;
    --border-strong: #2d3852;
    --text: #e6ebf5;
    --text-dim: #94a3b8;
    --text-mute: #64748b;
    --accent: #22d3ee;
    --accent-2: #06b6d4;
    --accent-glow: rgba(34, 211, 238, 0.18);
    --success: #34d399;
    --success-glow: rgba(52, 211, 153, 0.35);
    --warn: #fbbf24;
    --evade: #fbbf24;
    --trigger: #22d3ee;
    --gold: #fbbf24;
    --silver: #cbd5e1;
    --bronze: #d97706;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { font-size: 16px; }
  body {
    background: var(--bg);
    background-image:
      radial-gradient(at 20% -10%, rgba(34, 211, 238, 0.08) 0px, transparent 50%),
      radial-gradient(at 85% 5%, rgba(168, 85, 247, 0.06) 0px, transparent 50%);
    background-attachment: fixed;
    color: var(--text);
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    min-height: 100vh;
    padding: 2.5rem 3rem;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  .mono { font-family: 'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, monospace; }
  code { font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 0.875em; background: var(--surface-2); padding: 1px 6px; border-radius: 3px; color: var(--accent); }
  a { color: var(--accent); text-decoration: none; }

  /* ===== Header ===== */
  header { display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 2rem; padding-bottom: 1.5rem; border-bottom: 1px solid var(--border); }
  .brand h1 { font-size: 2rem; font-weight: 700; letter-spacing: -0.025em; }
  .brand h1 .accent { color: var(--accent); }
  .brand h1 .light { color: var(--text-mute); font-weight: 400; font-size: 1rem; margin-left: 0.5rem; }
  .brand .subtitle { color: var(--text-dim); font-size: 0.875rem; margin-top: 0.25rem; }
  .live { display: flex; align-items: center; gap: 0.5rem; color: var(--success); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.18em; font-weight: 600; }
  .live::before { content: ''; width: 8px; height: 8px; border-radius: 50%; background: var(--success); box-shadow: 0 0 10px var(--success-glow); animation: pulse 1.6s ease-in-out infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.5; transform: scale(1.2); } }
  .updated { color: var(--text-mute); font-size: 0.7rem; margin-top: 0.25rem; text-align: right; }

  /* ===== Stats ===== */
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.25rem 1.5rem; position: relative; overflow: hidden; }
  .stat::after { content: ''; position: absolute; top: 0; right: 0; width: 80px; height: 80px; background: radial-gradient(circle, var(--accent-glow) 0%, transparent 70%); pointer-events: none; }
  .stat .label { color: var(--text-mute); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.12em; font-weight: 500; margin-bottom: 0.25rem; }
  .stat .value { font-family: 'JetBrains Mono', monospace; font-size: 2rem; font-weight: 700; color: var(--text); }
  .stat .value .sub { color: var(--text-mute); font-size: 1rem; font-weight: 400; margin-left: 0.25rem; }

  /* ===== Panel ===== */
  .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 0.75rem; margin-bottom: 1.5rem; overflow: hidden; }
  .panel-header { padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
  .panel-header h2 { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.18em; color: var(--text-dim); font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }
  .panel-header h2::before { content: ''; width: 3px; height: 14px; background: var(--accent); border-radius: 2px; }
  .panel-aux { color: var(--text-mute); font-size: 0.75rem; font-family: 'JetBrains Mono', monospace; }

  /* ===== Leaderboard ===== */
  table { width: 100%; border-collapse: collapse; }
  thead th { color: var(--text-mute); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.12em; font-weight: 600; padding: 0.6rem 1.5rem; text-align: left; background: var(--bg-elev); }
  tbody tr { transition: background 0.2s; }
  tbody tr:hover { background: var(--surface-2); }
  tbody td { padding: 0.875rem 1.5rem; border-top: 1px solid var(--border); vertical-align: middle; }
  .rank { font-family: 'JetBrains Mono', monospace; font-size: 1.1rem; font-weight: 700; width: 60px; }
  .rank-1 { color: var(--gold); text-shadow: 0 0 8px rgba(251, 191, 36, 0.5); }
  .rank-2 { color: var(--silver); }
  .rank-3 { color: var(--bronze); }
  .user-cell { font-family: 'JetBrains Mono', monospace; font-weight: 600; font-size: 0.95rem; }
  .user-cell .avatar { display: inline-block; width: 24px; height: 24px; border-radius: 50%; background: linear-gradient(135deg, var(--accent), #a855f7); color: var(--bg); text-align: center; line-height: 24px; font-size: 0.7rem; margin-right: 0.5rem; vertical-align: -7px; font-weight: 700; }
  .score-cell { font-family: 'JetBrains Mono', monospace; font-size: 1rem; }
  .score-cell .total { color: var(--text-mute); }
  .progress { width: 100%; height: 6px; background: var(--surface-2); border-radius: 3px; overflow: hidden; min-width: 120px; }
  .progress-bar { height: 100%; background: linear-gradient(90deg, var(--accent-2), var(--accent)); border-radius: 3px; transition: width 0.7s cubic-bezier(0.4, 0, 0.2, 1); box-shadow: 0 0 8px var(--accent-glow); }
  .events-cell { color: var(--text-mute); font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; text-align: right; }

  /* ===== Challenges ===== */
  .challenges { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; padding: 1.25rem 1.5rem; }
  .challenge { background: var(--bg-elev); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1rem; transition: all 0.2s; position: relative; }
  .challenge:hover { border-color: var(--border-strong); transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3); }
  .challenge.full { border-color: var(--success); background: linear-gradient(135deg, var(--bg-elev) 0%, rgba(52, 211, 153, 0.05) 100%); }
  .challenge .head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
  .challenge .num { font-family: 'JetBrains Mono', monospace; color: var(--text-mute); font-size: 0.75rem; font-weight: 600; letter-spacing: 0.05em; }
  .badge { padding: 3px 9px; border-radius: 4px; font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; }
  .badge-trigger { background: rgba(34, 211, 238, 0.12); color: var(--trigger); border: 1px solid rgba(34, 211, 238, 0.3); }
  .badge-evade { background: rgba(251, 191, 36, 0.12); color: var(--evade); border: 1px solid rgba(251, 191, 36, 0.3); }
  .challenge .name { font-weight: 600; margin-bottom: 0.5rem; color: var(--text); font-size: 0.95rem; }
  .challenge .rule { color: var(--text-dim); font-size: 0.7rem; font-family: 'JetBrains Mono', monospace; margin-bottom: 0.75rem; line-height: 1.4; word-break: break-word; }
  .challenge .dots { display: flex; gap: 5px; margin-bottom: 0.5rem; }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--border-strong); transition: all 0.3s; }
  .dot.filled { background: var(--success); box-shadow: 0 0 6px var(--success-glow); }
  .challenge .footer { display: flex; justify-content: space-between; font-size: 0.7rem; color: var(--text-mute); font-family: 'JetBrains Mono', monospace; }
  .challenge .footer .solved-count { color: var(--success); font-weight: 600; }

  /* ===== Activity ===== */
  .activity { padding: 0.5rem 0; max-height: 480px; overflow-y: auto; }
  .activity::-webkit-scrollbar { width: 6px; }
  .activity::-webkit-scrollbar-track { background: transparent; }
  .activity::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 3px; }
  .activity-item { display: flex; justify-content: space-between; align-items: center; padding: 0.65rem 1.5rem; gap: 1rem; border-left: 2px solid transparent; transition: all 0.2s; }
  .activity-item:hover { background: var(--surface-2); border-left-color: var(--accent); }
  .activity-item.fresh { animation: flash 1.2s ease; }
  @keyframes flash {
    0% { background: var(--accent-glow); border-left-color: var(--accent); box-shadow: inset 0 0 24px var(--accent-glow); }
    100% { background: transparent; border-left-color: transparent; box-shadow: none; }
  }
  .activity-item .who { font-family: 'JetBrains Mono', monospace; font-weight: 600; color: var(--text); }
  .activity-item .verb { color: var(--text-mute); font-size: 0.8rem; margin: 0 0.5rem; }
  .activity-item .what { color: var(--accent); font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; }
  .activity-item .when { color: var(--text-mute); font-size: 0.7rem; font-family: 'JetBrains Mono', monospace; flex-shrink: 0; }

  /* ===== Grid ===== */
  .grid { display: grid; grid-template-columns: 1.7fr 1fr; gap: 1.5rem; }
  @media (max-width: 980px) {
    body { padding: 1.25rem; }
    .grid { grid-template-columns: 1fr; }
    .stats { grid-template-columns: repeat(2, 1fr); }
  }

  .empty { text-align: center; padding: 2.5rem 1rem; color: var(--text-mute); font-size: 0.875rem; }
  .empty .icon { font-size: 2rem; opacity: 0.4; display: block; margin-bottom: 0.5rem; }
</style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>falco<span class="accent">-ctf</span> <span class="light mono">scoreboard</span></h1>
      <div class="subtitle">Capture the Flag · Runtime detection challenge</div>
    </div>
    <div>
      <div class="live">● LIVE</div>
      <div class="updated mono" id="updated">connecting…</div>
    </div>
  </header>

  <section class="stats" id="stats"></section>

  <section class="panel">
    <div class="panel-header">
      <h2>Leaderboard</h2>
      <span class="panel-aux" id="lb-meta"></span>
    </div>
    <table>
      <thead><tr>
        <th style="width:60px">Rank</th>
        <th>Participant</th>
        <th>Solved</th>
        <th style="width:30%">Progress</th>
        <th style="text-align:right">Events</th>
      </tr></thead>
      <tbody id="lb-body"></tbody>
    </table>
  </section>

  <section class="grid">
    <div class="panel">
      <div class="panel-header"><h2>Challenges</h2><span class="panel-aux" id="ch-meta"></span></div>
      <div class="challenges" id="challenges"></div>
    </div>
    <div class="panel">
      <div class="panel-header"><h2>Recent activity</h2><span class="panel-aux" id="act-meta"></span></div>
      <div class="activity" id="activity"></div>
    </div>
  </section>

<script>
  // ---------------- helpers ----------------
  const seen = new Set();
  let firstRender = true;
  function fmtAgo(iso) {
    const ms = Date.now() - new Date(iso).getTime();
    const s = Math.max(0, Math.floor(ms / 1000));
    if (s < 5)    return 'just now';
    if (s < 60)   return s + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }
  function esc(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  function avatarChar(u) { return (u || '?').slice(-1).toUpperCase(); }

  // ---------------- fetch loop ----------------
  async function refresh() {
    try {
      const r = await fetch('/api/state');
      if (!r.ok) throw new Error('HTTP ' + r.status);
      render(await r.json());
      document.getElementById('updated').textContent = 'updated ' + new Date().toLocaleTimeString();
    } catch (e) {
      document.getElementById('updated').textContent = 'connection error';
    }
  }

  function render(d) {
    const totalChal = d.stats.challenges;
    const totalUsers = d.stats.users;
    const maxPossible = totalChal * totalUsers;

    // ---- stats ----
    document.getElementById('stats').innerHTML = `
      <div class="stat"><div class="label">Participants</div><div class="value">${d.stats.users}</div></div>
      <div class="stat"><div class="label">Challenges</div><div class="value">${d.stats.challenges}</div></div>
      <div class="stat"><div class="label">Total solves</div><div class="value">${d.stats.solves}<span class="sub">/ ${maxPossible || '—'}</span></div></div>
      <div class="stat"><div class="label">Falco events</div><div class="value">${d.stats.events.toLocaleString()}</div></div>
    `;

    // ---- leaderboard ----
    document.getElementById('lb-meta').textContent = totalUsers + ' participants';
    const lb = document.getElementById('lb-body');
    if (d.leaderboard.length === 0) {
      lb.innerHTML = '<tr><td colspan="5" class="empty"><span class="icon">∅</span>No participants yet — deploy a workspace to begin</td></tr>';
    } else {
      lb.innerHTML = d.leaderboard.map(p => {
        const pct = totalChal ? Math.round(100 * p.solved / totalChal) : 0;
        const rankCls = p.rank <= 3 ? 'rank-' + p.rank : '';
        return `<tr>
          <td><span class="rank ${rankCls}">#${p.rank}</span></td>
          <td><span class="user-cell"><span class="avatar">${avatarChar(p.user)}</span>${esc(p.user)}</span></td>
          <td><span class="score-cell">${p.solved}<span class="total">/${totalChal}</span></span></td>
          <td><div class="progress"><div class="progress-bar" style="width:${pct}%"></div></div></td>
          <td><span class="events-cell">${p.events.toLocaleString()}</span></td>
        </tr>`;
      }).join('');
    }

    // ---- challenges ----
    document.getElementById('ch-meta').textContent = d.challenges.length + ' total';
    const ch = document.getElementById('challenges');
    if (d.challenges.length === 0) {
      ch.innerHTML = '<div class="empty"><span class="icon">∅</span>No challenges loaded</div>';
    } else {
      ch.innerHTML = d.challenges.map(c => {
        const parts = c.id.split('-');
        const num = parts[0];
        const slug = parts.slice(1).join('-');
        const dots = Array.from({length: Math.max(totalUsers, 1)}, (_, i) =>
          `<span class="dot${i < c.solved_count ? ' filled' : ''}"></span>`).join('');
        const rule = c.expectedRules[0] || c.forbiddenRules[0] || '';
        const full = totalUsers > 0 && c.solved_count >= totalUsers ? ' full' : '';
        const prefix = c.type === 'evade' ? '✗ ' : '✓ ';
        return `<div class="challenge${full}">
          <div class="head">
            <span class="num">${esc(num)}</span>
            <span class="badge badge-${c.type}">${c.type}</span>
          </div>
          <div class="name">${esc(slug)}</div>
          <div class="rule">${esc(prefix + rule)}</div>
          <div class="dots">${dots}</div>
          <div class="footer">
            <span><span class="solved-count">${c.solved_count}</span> / ${totalUsers || '?'} solved</span>
            <span>${c.first_solver ? '🏆 ' + esc(c.first_solver) : '—'}</span>
          </div>
        </div>`;
      }).join('');
    }

    // ---- activity ----
    document.getElementById('act-meta').textContent = d.recent_solves.length + ' shown';
    const act = document.getElementById('activity');
    if (d.recent_solves.length === 0) {
      act.innerHTML = '<div class="empty"><span class="icon">∅</span>No solves yet</div>';
    } else {
      act.innerHTML = d.recent_solves.map(s => {
        const key = s.user + ':' + s.challenge;
        const fresh = !firstRender && !seen.has(key);
        seen.add(key);
        return `<div class="activity-item${fresh ? ' fresh' : ''}">
          <div style="min-width:0">
            <span class="who">${esc(s.user)}</span>
            <span class="verb">solved</span>
            <span class="what">${esc(s.challenge)}</span>
          </div>
          <span class="when" title="${esc(s.at)}">${fmtAgo(s.at)}</span>
        </div>`;
      }).join('');
    }
    firstRender = false;
  }

  refresh();
  setInterval(refresh, 2000);
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _INDEX_HTML
