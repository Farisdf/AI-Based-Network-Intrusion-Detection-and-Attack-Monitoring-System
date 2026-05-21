"""
Web dashboard for the network IDS.

Reads threat_log.csv (written by alerting.py) and serves a live, auto-
refreshing page that lists every detected attack plus summary statistics.

Run it in its own terminal alongside the IDS:

    python dashboard.py

then open http://127.0.0.1:5000 in a browser.
"""

import os

try:
    from flask import Flask, jsonify
except ImportError:
    raise SystemExit("[ERROR] Flask is not installed. Run:  pip install flask")

import pandas as pd

LOG_FILE = "threat_log.csv"
COLUMNS = ["timestamp", "ip", "direction", "threat_type", "severity", "score", "description"]
HOST = "127.0.0.1"   # local only; change to "0.0.0.0" to expose on the LAN
PORT = 5000

app = Flask(__name__)


def load_alerts():
    """Load threat_log.csv into a DataFrame, tolerating an empty/locked file."""
    if not os.path.isfile(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
        return pd.DataFrame(columns=COLUMNS)
    try:
        df = pd.read_csv(LOG_FILE, on_bad_lines="skip")
    except Exception:
        return pd.DataFrame(columns=COLUMNS)

    # Make sure every expected column exists, then normalise types.
    for col in COLUMNS:
        if col not in df.columns:
            df[col] = ""
    df = df[COLUMNS]
    df["score"] = pd.to_numeric(df["score"], errors="coerce").fillna(0).astype(int)
    for col in ["timestamp", "ip", "direction", "threat_type", "severity", "description"]:
        df[col] = df[col].fillna("").astype(str)
    return df


@app.route("/api/data")
def api_data():
    """JSON feed consumed by the dashboard page."""
    df = load_alerts()
    if len(df):
        df = df.sort_values("timestamp", ascending=False)

    total = len(df)
    stats = {
        "total": total,
        "unique_ips": int(df["ip"].nunique()) if total else 0,
        "inbound": int((df["direction"] == "inbound").sum()),
        "outbound": int((df["direction"] == "outbound").sum()),
        "high": int((df["severity"] == "high").sum()),
        "last": df["timestamp"].iloc[0] if total else "",
    }

    if total:
        top = df.groupby("ip").size().sort_values(ascending=False).head(10)
        top_attackers = [{"ip": ip, "count": int(c)} for ip, c in top.items()]
    else:
        top_attackers = []

    alerts = []
    for rec in df.head(200).to_dict(orient="records"):
        rec["score"] = int(rec["score"])
        alerts.append(rec)

    return jsonify(stats=stats, alerts=alerts, top_attackers=top_attackers)


@app.route("/")
def index():
    """Serve the single-page dashboard."""
    return PAGE


PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network IDS Dashboard</title>
<style>
  :root {
    --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3;
    --muted:#8b949e; --high:#f85149; --med:#d29922; --low:#3fb950; --accent:#58a6ff;
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text);
         font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif; padding:24px; }
  h1 { font-size:21px; }
  .sub { color:var(--muted); font-size:13px; margin:4px 0 20px; }
  .dot { height:8px; width:8px; background:var(--low); border-radius:50%;
         display:inline-block; margin-right:6px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
           gap:14px; margin-bottom:22px; }
  .card { background:var(--card); border:1px solid var(--border);
          border-radius:10px; padding:16px; }
  .card .label { color:var(--muted); font-size:11px; text-transform:uppercase;
                 letter-spacing:.6px; }
  .card .value { font-size:26px; font-weight:600; margin-top:6px;
                 word-break:break-word; }
  .layout { display:grid; grid-template-columns:2fr 1fr; gap:18px; }
  @media (max-width:880px){ .layout{ grid-template-columns:1fr; } }
  .panel { background:var(--card); border:1px solid var(--border);
           border-radius:10px; padding:16px; }
  .panel h2 { font-size:13px; color:var(--muted); text-transform:uppercase;
              letter-spacing:.6px; margin-bottom:12px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th { text-align:left; color:var(--muted); font-weight:500; padding:8px;
       border-bottom:1px solid var(--border); }
  td { padding:8px; border-bottom:1px solid var(--border); }
  tr:last-child td { border-bottom:none; }
  .ip { font-family:Consolas,'Courier New',monospace; }
  .badge { padding:2px 9px; border-radius:20px; font-size:11px; font-weight:600; }
  .high   { background:rgba(248,81,73,.15);  color:var(--high); }
  .medium { background:rgba(210,153,34,.15); color:var(--med); }
  .low    { background:rgba(63,185,80,.15);  color:var(--low); }
  .dir-inbound  { color:var(--high); }
  .dir-outbound { color:var(--accent); }
  .dir-local    { color:var(--muted); }
  .filters { margin-bottom:12px; }
  .filters button { background:var(--bg); color:var(--muted);
    border:1px solid var(--border); padding:5px 12px; border-radius:6px;
    cursor:pointer; font-size:12px; margin-right:6px; }
  .filters button.active { background:var(--accent); color:#fff;
    border-color:var(--accent); }
  .empty { color:var(--muted); text-align:center; padding:28px; }
</style>
</head>
<body>
  <h1>&#128737; Network IDS Dashboard</h1>
  <div class="sub"><span class="dot"></span>Live &middot; auto-refresh every 5s &middot;
       <span id="updated">connecting...</span></div>

  <div class="cards" id="cards"></div>

  <div class="layout">
    <div class="panel">
      <h2>Detected Attacks</h2>
      <div class="filters" id="filters">
        <button data-f="all" class="active">All</button>
        <button data-f="inbound">Inbound</button>
        <button data-f="outbound">Outbound</button>
        <button data-f="high">High severity</button>
      </div>
      <table>
        <thead><tr>
          <th>Time</th><th>IP</th><th>Direction</th>
          <th>Type</th><th>Severity</th><th>Score</th>
        </tr></thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    <div class="panel">
      <h2>Top Attackers</h2>
      <table>
        <thead><tr><th>IP</th><th>Hits</th></tr></thead>
        <tbody id="top"></tbody>
      </table>
    </div>
  </div>

<script>
  let allAlerts = [], filter = 'all';

  function fmtTime(t) {
    if (!t) return '\\u2014';
    return t.replace('T', ' ').slice(0, 19);
  }

  function render() {
    let data = allAlerts;
    if (filter === 'inbound')  data = data.filter(a => a.direction === 'inbound');
    if (filter === 'outbound') data = data.filter(a => a.direction === 'outbound');
    if (filter === 'high')     data = data.filter(a => a.severity === 'high');

    const rows = document.getElementById('rows');
    if (!data.length) {
      rows.innerHTML = '<tr><td colspan="6" class="empty">No attacks detected yet.</td></tr>';
      return;
    }
    rows.innerHTML = data.map(a => `
      <tr>
        <td>${fmtTime(a.timestamp)}</td>
        <td class="ip">${a.ip}</td>
        <td class="dir-${a.direction}">${a.direction}</td>
        <td>${a.threat_type}</td>
        <td><span class="badge ${a.severity}">${a.severity}</span></td>
        <td>${a.score}</td>
      </tr>`).join('');
  }

  async function refresh() {
    try {
      const res = await fetch('/api/data');
      const d = await res.json();
      allAlerts = d.alerts;

      const s = d.stats;
      document.getElementById('cards').innerHTML = [
        ['Total alerts', s.total],
        ['Unique attackers', s.unique_ips],
        ['Inbound', s.inbound],
        ['Outbound', s.outbound],
        ['High severity', s.high],
        ['Last alert', fmtTime(s.last)]
      ].map(([l, v]) =>
        `<div class="card"><div class="label">${l}</div>
         <div class="value">${v}</div></div>`).join('');

      const top = document.getElementById('top');
      top.innerHTML = d.top_attackers.length
        ? d.top_attackers.map(t =>
            `<tr><td class="ip">${t.ip}</td><td>${t.count}</td></tr>`).join('')
        : '<tr><td colspan="2" class="empty">\\u2014</td></tr>';

      document.getElementById('updated').textContent =
        'updated ' + new Date().toLocaleTimeString();
      render();
    } catch (e) {
      document.getElementById('updated').textContent = 'connection error';
    }
  }

  document.querySelectorAll('#filters button').forEach(b => {
    b.onclick = () => {
      document.querySelectorAll('#filters button')
        .forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      filter = b.dataset.f;
      render();
    };
  });

  refresh();
  setInterval(refresh, 5000);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    print(f"[*] IDS dashboard running at http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)
