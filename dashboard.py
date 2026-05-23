"""
Web dashboard for the network IDS.

Reads threat_log.csv (written by alerting.py) and serves a live, auto-
refreshing page that lists every detected attack plus summary statistics.

Run it in its own terminal alongside the IDS:

    python dashboard.py

then open http://127.0.0.1:5000 in a browser.
"""

import csv
import os
import re
import shutil

try:
    from flask import Flask, jsonify, request
except ImportError:
    raise SystemExit("[ERROR] Flask is not installed. Run:  pip install flask")

from datetime import datetime
import pandas as pd

LOG_FILE = "threat_log.csv"
COLUMNS = ["timestamp", "ip", "direction", "threat_type", "severity", "score", "description"]
HOST = "127.0.0.1"   # local only; change to "0.0.0.0" to expose on the LAN
PORT = 5000

# Backup files are written as threat_log.csv.bak-YYYYMMDD-HHMMSS - we only
# accept that exact pattern in /analyze/ to block directory traversal.
BACKUP_RE = re.compile(r"^threat_log\.csv\.bak-\d{8}-\d{6}$")

app = Flask(__name__)


def calculate_risk(threat_type, severity, score):
    """
    Risk score on a 0-100 scale. Combines:

      * severity label (low/medium/high)   - baseline 20 / 45 / 65
      * threat type                        - DoS > brute > scan > rep
      * intensity (`score`)                - how far past the trigger threshold

    Returns an int 0-100. Same fields, same answer every time.
    """
    sev_base = {"low": 20, "medium": 45, "high": 65}.get(
        str(severity).lower(), 30
    )
    t = str(threat_type).lower()
    try:
        s = int(score)
    except (TypeError, ValueError):
        s = 0

    if "dos" in t or "flood" in t:
        type_boost = 20
        intensity  = min(15, s // 80)                    # 500 pkts -> +6, 1200 -> +15
    elif "brute" in t:
        type_boost = 15
        intensity  = min(15, max(0, (s - 10) * 2))       # threshold is 10 attempts
    elif "port scan" in t:
        type_boost = 12
        intensity  = min(15, max(0, s - 15))             # threshold is 15 ports
    elif "malicious" in t:
        type_boost = min(25, s)                          # IPsum score is the input
        intensity  = 0
    else:
        type_boost = 0
        intensity  = 0

    return int(max(0, min(100, sev_base + type_boost + intensity)))


def load_alerts(path=None):
    """Load a threat-log CSV into a DataFrame, tolerating an empty/locked file."""
    p = path or LOG_FILE
    if not os.path.isfile(p) or os.path.getsize(p) == 0:
        return pd.DataFrame(columns=COLUMNS + ["risk"])
    try:
        df = pd.read_csv(p, on_bad_lines="skip")
    except Exception:
        return pd.DataFrame(columns=COLUMNS + ["risk"])

    # Make sure every expected column exists, then normalise types.
    for col in COLUMNS:
        if col not in df.columns:
            df[col] = ""
    df = df[COLUMNS]
    df["score"] = pd.to_numeric(df["score"], errors="coerce").fillna(0).astype(int)
    for col in ["timestamp", "ip", "direction", "threat_type", "severity", "description"]:
        df[col] = df[col].fillna("").astype(str)
    df["risk"] = df.apply(
        lambda r: calculate_risk(r["threat_type"], r["severity"], r["score"]),
        axis=1,
    ).astype(int)
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
        "max_risk": int(df["risk"].max()) if total else 0,
        "avg_risk": int(round(df["risk"].mean())) if total else 0,
    }

    if total:
        top = df.groupby("ip").size().sort_values(ascending=False).head(10)
        top_attackers = [{"ip": ip, "count": int(c)} for ip, c in top.items()]
    else:
        top_attackers = []

    alerts = []
    for rec in df.head(200).to_dict(orient="records"):
        rec["score"] = int(rec["score"])
        rec["risk"]  = int(rec["risk"])
        alerts.append(rec)

    return jsonify(stats=stats, alerts=alerts, top_attackers=top_attackers)


ATTACK_INFO = {
    "portscan": {
        "title": "Port Scan",
        "icon": "&#128269;",
        "color": "#58a6ff",
        "tagline": "Reconnaissance - mapping what services a target is running.",
        "summary": (
            "A port scan is an attacker probing many TCP/UDP ports on a "
            "target to find which services are listening. It's almost always "
            "the first step before a real attack - the attacker needs to "
            "know what's exposed before they can try to exploit it."
        ),
        "sections": [
            ("How it works", [
                "TCP SYN scan: send a SYN, an open port replies SYN-ACK, a closed port replies RST.",
                "TCP connect scan: complete the 3-way handshake (noisier, easier to log).",
                "UDP scan: send empty UDP packets; closed ports return ICMP unreachable, open ports are silent.",
                "Stealth variants (FIN, NULL, Xmas scan) set unusual TCP flag combinations to evade older firewalls.",
                "Common tools: nmap, masscan, zmap, unicornscan.",
            ]),
            ("Signs of attack", [
                "Many short connection attempts from one source IP to many different destination ports in a short window.",
                "Lots of SYNs without follow-up data - half-open connections.",
                "Probes often hit sequential ports or a well-known service list (22, 80, 443, 3389, ...).",
            ]),
            ("How this IDS detects it", [
                "<code>detectors.py</code> counts the distinct destination ports each source IP has touched in a 10-second sliding window.",
                "If one IP touches <b>15 or more</b> distinct ports in that window, a <b>Port scan</b> alert is raised.",
                "Detection works identically for live capture and pcap replay because the window is keyed off each packet's capture timestamp.",
            ]),
            ("How to defend", [
                "Only run services you actually need - the less exposed, the less to scan.",
                "Rate-limit new connections per source IP at the firewall.",
                "Drop traffic to closed ports silently (no RST reply) - it slows scanners and hides what's really closed vs filtered.",
                "Hide sensitive admin services (SSH, RDP, database) behind a VPN or port-knocking.",
                "Subscribe to threat feeds (this IDS uses IPsum) - block IPs that other defenders have already seen scanning.",
            ]),
            ("Awareness", [
                "A port scan from a residential / cloud IP is almost never benign - treat it as reconnaissance.",
                "If you see one, escalate alerting on that IP for the next hour; the actual exploit attempt usually follows quickly.",
                "Scanning the public internet is not illegal in most places, but scanning a network you don't own is - keep your scanning to lab environments.",
            ]),
        ],
    },
    "dos": {
        "title": "Denial of Service (DoS / Flood)",
        "icon": "&#128165;",
        "color": "#f85149",
        "tagline": "Overwhelm a service so legitimate users can't reach it.",
        "summary": (
            "A DoS attack doesn't try to steal data - it tries to break "
            "availability. By sending more traffic than the target can "
            "handle (or by exhausting some other resource like the TCP "
            "connection table), the attacker makes the service unreachable "
            "for real users. When the flood comes from many sources at "
            "once it's called DDoS (Distributed DoS)."
        ),
        "sections": [
            ("How it works", [
                "Volumetric flood: just send more packets/bandwidth than the link can carry.",
                "SYN flood: open thousands of half-finished TCP connections, exhausting the server's connection table.",
                "Application flood: send valid-looking requests (HTTP GET, DNS queries) faster than the app can serve them.",
                "Amplification: send a small spoofed request to an open server (DNS, NTP, memcached) - the reply, sent to the victim, is many times bigger.",
                "Common tools: hping3, LOIC, HOIC, Slowloris, t50.",
            ]),
            ("Signs of attack", [
                "Sudden spike of packets from one (DoS) or many (DDoS) source IPs.",
                "Server connection table fills up; legitimate users get timeouts.",
                "Lots of TCP SYNs with no matching ACKs - incomplete handshakes.",
                "CPU/memory or bandwidth saturation on the target.",
            ]),
            ("How this IDS detects it", [
                "<code>detectors.py</code> tracks packets-per-source-IP and SYNs-per-source-IP in a 10-second window.",
                "<b>500</b> packets in 10s from one IP -> <b>DoS / packet flood</b> alert.",
                "<b>100</b> TCP SYNs in 10s from one IP -> <b>DoS / SYN flood</b> alert.",
                "Both thresholds are tunable constants at the top of <code>detectors.py</code>.",
            ]),
            ("How to defend", [
                "Enable SYN cookies (on by default in modern Linux + most web servers) to survive SYN floods.",
                "Rate-limit connections per source IP and per /24 subnet.",
                "Put public services behind a CDN / scrubbing provider (Cloudflare, AWS Shield, Akamai).",
                "Drop spoofed source addresses at the network edge (BCP38 ingress filtering).",
                "Have an incident response plan - mitigation during an active attack is slow.",
            ]),
            ("Awareness", [
                "A single-source DoS is usually amateur. Serious adversaries use DDoS with thousands of compromised hosts.",
                "Source IPs in floods are often spoofed or compromised, so attribution is hard.",
                "You don't 'block' a flood - you absorb it or scrub it upstream. The traffic still costs your bandwidth even if your server stays up.",
            ]),
        ],
    },
    "bruteforce": {
        "title": "Brute Force Login",
        "icon": "&#128274;",
        "color": "#d29922",
        "tagline": "Try password after password until one works.",
        "summary": (
            "Brute force attacks aim at authentication: the attacker keeps "
            "trying credentials against a login service (SSH, RDP, web "
            "admin, database) until they find a working one. Most modern "
            "attacks don't try random passwords - they use leaked password "
            "lists and known username conventions."
        ),
        "sections": [
            ("How it works", [
                "Online brute force: hit the live login service - slow, but no need to steal hashes first.",
                "Dictionary attack: try the top 10,000 most common passwords.",
                "Credential stuffing: use username/password pairs leaked in other companies' breaches (people reuse passwords).",
                "Hybrid: dictionary + mutations like <code>Password1</code>, <code>P@ssw0rd!</code>, <code>Summer2024</code>.",
                "Common tools: hydra, medusa, ncrack, patator, John the Ripper (offline).",
            ]),
            ("Signs of attack", [
                "Many connection attempts to a login port (22 SSH, 3389 RDP, 21 FTP, 3306 MySQL, etc.) from one source.",
                "High failed-login rate from one IP.",
                "Failed logins in rapid succession (much faster than a human types).",
            ]),
            ("How this IDS detects it", [
                "<code>detectors.py</code> watches TCP SYNs to a list of well-known service ports (22, 23, 3306, 3389, 5900, ...).",
                "<b>10 or more</b> connection attempts to one login service from one IP in <b>30 seconds</b> raises a <b>Brute force</b> alert.",
                "The service name (SSH, MySQL, RDP, ...) appears in the alert description.",
            ]),
            ("How to defend", [
                "Disable password authentication where possible - SSH should use keys only.",
                "Require MFA on every account that has a remote login.",
                "Use <code>fail2ban</code> or <code>sshguard</code> to auto-ban IPs after a few failed attempts.",
                "Lock the account temporarily after N failed attempts (careful - this can be weaponised into a DoS).",
                "Move SSH/RDP off default ports - cuts ~95% of internet background scans even though it isn't real security.",
                "Put admin services behind a VPN; never expose RDP or DB ports to the open internet.",
            ]),
            ("Awareness", [
                "Any public-facing SSH or RDP box sees brute force constantly - it's background noise on the internet.",
                "The risk isn't whether attackers try, it's whether they succeed. Audit successful logins, not just failures.",
                "Strong unique passwords + MFA make online brute force ineffective. Use a password manager.",
            ]),
        ],
    },
    "malicious-ip": {
        "title": "Known Malicious IP",
        "icon": "&#127919;",
        "color": "#f0883e",
        "tagline": "Communication with an IP that's on a threat-intelligence blocklist.",
        "summary": (
            "A 'malicious IP' alert means the source (or destination) of "
            "traffic appears on a published blocklist of bad actors - hosts "
            "seen scanning, attacking, or running command-and-control in "
            "other networks. This IDS uses the IPsum feed, which aggregates "
            "30+ public blocklists. Each IP's score is the number of lists "
            "it appears on - higher score = higher confidence it's bad."
        ),
        "sections": [
            ("How it works", [
                "Threat feeds aggregate observations from honeypots, malware sandbox detonations, and security-vendor telemetry.",
                "An IP that gets reported by many independent sources is much more likely to be genuinely malicious than one on a single list.",
                "Feeds get stale fast - this IDS re-downloads IPsum at startup (and can be re-run any time) to refresh <code>Malicious_IP.csv</code>.",
                "The <code>min_score</code> setting filters out low-confidence entries (default: only keep IPs appearing on 3+ lists).",
            ]),
            ("Signs of attack", [
                "<b>Inbound (Malicious source IP):</b> incoming traffic from a known-bad IP. Often a scan, exploit attempt, or generic internet noise.",
                "<b>Outbound (Malicious destination IP):</b> your machine reaching out to a known-bad IP. <b>This is much scarier</b> - it can mean malware on your host is calling home to a C2 server.",
                "Sudden burst of connections to/from an IP you don't recognise.",
            ]),
            ("How this IDS detects it", [
                "<code>Check_IP.py</code> looks up the source and destination IP of every packet in <code>Malicious_IP.csv</code>.",
                "If listed, <code>alerting.py</code> records a <b>Malicious source IP</b> (inbound) or <b>Malicious destination IP</b> (outbound) alert.",
                "Severity comes from the IPsum score: 8+ = high, 4-7 = medium, below = low.",
            ]),
            ("How to defend", [
                "Block listed IPs at the firewall outright - threat feed -> firewall rule.",
                "<b>For outbound hits especially: investigate the local process.</b> Find which program on your machine is making that connection (<code>netstat</code>, <code>Resource Monitor</code>, <code>lsof</code>).",
                "Keep threat feeds updated; old data has high false-positive rates.",
                "Consider commercial threat intel for higher-quality, faster updates (CrowdStrike, Recorded Future, MISP communities).",
            ]),
            ("Awareness", [
                "Threat feeds have false positives - a legitimate company on a flagged hosting IP, an old listing that's now clean. Investigate before you block in production.",
                "IP reputation is a blunt tool; sophisticated attackers cycle IPs constantly.",
                "Outbound to a known-bad IP is almost always more concerning than inbound from one - inbound is just internet noise; outbound usually means something on YOUR side initiated it.",
            ]),
        ],
    },
}


def render_info_page(key, data):
    """Build the attack-awareness HTML page from an ATTACK_INFO entry."""
    sections_html = "".join(
        f"""
        <div class="info-panel">
          <h2>{title}</h2>
          <ul>{''.join(f'<li>{item}</li>' for item in items)}</ul>
        </div>
        """
        for title, items in data["sections"]
    )
    return INFO_PAGE_TEMPLATE.format(
        key=key,
        title=data["title"],
        icon=data["icon"],
        color=data["color"],
        tagline=data["tagline"],
        summary=data["summary"],
        sections=sections_html,
    )


@app.route("/info/<key>")
def info_page(key):
    """Educational details + awareness for a given attack type."""
    data = ATTACK_INFO.get(key)
    if data is None:
        return (f"<p style='font-family:sans-serif;padding:24px;color:#e6edf3;"
                f"background:#0d1117;min-height:100vh;margin:0;'>"
                f"Unknown attack type: <code>{key}</code>. "
                f"<a href='/' style='color:#58a6ff;'>Back to dashboard</a></p>",
                404)
    return render_info_page(key, data)


@app.route("/api/reset-log", methods=["POST"])
def reset_log():
    """Clear threat_log.csv. If save=true (default), copy it to a timestamped
    backup first so it can be opened on the /analyze/<filename> page."""
    payload = request.get_json(silent=True) or {}
    save = bool(payload.get("save", True))
    backup_name = None
    try:
        if save and os.path.isfile(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
            backup_name = f"{LOG_FILE}.bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            shutil.copy2(LOG_FILE, backup_name)
        with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(COLUMNS)
        return jsonify(ok=True, backup=os.path.basename(backup_name) if backup_name else None)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


def _humanize_bak_timestamp(filename):
    """Pull the YYYYMMDD-HHMMSS suffix out of a backup filename and format it."""
    m = re.search(r"bak-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})$", filename)
    if not m:
        return ""
    y, mo, d, h, mi, s = m.groups()
    return f"{y}-{mo}-{d} {h}:{mi}:{s}"


@app.route("/analyze/<path:filename>")
def analyze_page(filename):
    """Read-only analysis view of a saved backup."""
    if not BACKUP_RE.match(filename):
        return ("<p style='color:#e6edf3;background:#0d1117;padding:24px;"
                "font-family:sans-serif;margin:0;min-height:100vh;'>"
                "Invalid backup filename. <a href='/' style='color:#58a6ff'>"
                "Back to dashboard</a></p>"), 400
    if not os.path.isfile(filename):
        return ("<p style='color:#e6edf3;background:#0d1117;padding:24px;"
                "font-family:sans-serif;margin:0;min-height:100vh;'>"
                f"Backup not found: <code>{filename}</code>. "
                "<a href='/' style='color:#58a6ff'>Back to dashboard</a></p>"), 404

    df = load_alerts(filename)
    total = len(df)
    if total:
        df = df.sort_values("timestamp", ascending=False)

    # Top-line stats.
    stats = {
        "total":      total,
        "unique_ips": int(df["ip"].nunique()) if total else 0,
        "inbound":    int((df["direction"] == "inbound").sum()),
        "outbound":   int((df["direction"] == "outbound").sum()),
        "high":       int((df["severity"] == "high").sum()),
        "medium":     int((df["severity"] == "medium").sum()),
        "low":        int((df["severity"] == "low").sum()),
        "max_risk":   int(df["risk"].max()) if total else 0,
        "avg_risk":   int(round(df["risk"].mean())) if total else 0,
        "first":      df["timestamp"].iloc[-1] if total else "",
        "last":       df["timestamp"].iloc[0]  if total else "",
    }

    # Threat-type breakdown and top attackers.
    if total:
        by_type = df.groupby("threat_type").size().sort_values(ascending=False)
        type_max = int(by_type.max())
        by_type_list = [
            {"label": str(label),
             "count": int(c),
             "pct":   int(round(100 * c / type_max))}
            for label, c in by_type.items()
        ]
        top = df.groupby("ip").size().sort_values(ascending=False).head(10)
        top_attackers = [{"ip": str(ip), "count": int(c)} for ip, c in top.items()]
    else:
        by_type_list, top_attackers = [], []

    alerts = []
    for rec in df.to_dict(orient="records"):
        rec["score"] = int(rec["score"])
        rec["risk"]  = int(rec["risk"])
        alerts.append(rec)

    import json
    html = ANALYZE_PAGE.replace(
        "__PAYLOAD__",
        json.dumps({
            "filename":      filename,
            "saved_at":      _humanize_bak_timestamp(filename),
            "stats":         stats,
            "alerts":        alerts,
            "by_type":       by_type_list,
            "top_attackers": top_attackers,
        }),
    )
    # Stop the browser caching an older response - the page is dynamic.
    resp = app.make_response(html)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"]        = "no-cache"
    resp.headers["Expires"]       = "0"
    return resp


@app.route("/api/topology-feed")
def topology_feed():
    """
    Incremental feed for the topology page. Returns alerts whose timestamp
    is strictly greater than `since` (ISO string), plus the server's current
    timestamp so the client can use it as the next `since`.

    On first load the client calls this with no `since` and just stores the
    returned `now` as its high-water mark - so the page doesn't replay the
    entire historical log.
    """
    since = request.args.get("since", "")
    df = load_alerts()
    now_iso = datetime.now().isoformat()

    alerts = []
    if since and len(df):
        df = df[df["timestamp"] > since]
        df = df.sort_values("timestamp", ascending=True)
        for rec in df.head(50).to_dict(orient="records"):
            rec["score"] = int(rec["score"])
            rec["risk"]  = int(rec["risk"])
            alerts.append(rec)

    return jsonify(alerts=alerts, now=now_iso)


@app.route("/")
def index():
    """Serve the single-page dashboard."""
    return PAGE


@app.route("/topology")
def topology():
    """Animated attack-topology simulation page."""
    return TOPOLOGY_PAGE


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
  tr.clickable { cursor:pointer; transition:background .15s; }
  tr.clickable:hover { background:rgba(88,166,255,.08); }
  tr.clickable td:first-child::before { content:'\\25B6'; color:var(--accent);
    opacity:0; margin-right:6px; font-size:10px; transition:opacity .15s; }
  tr.clickable:hover td:first-child::before { opacity:1; }
  .attack-link { color:var(--text); cursor:help; text-decoration:none;
                 border-bottom:1px dotted var(--muted); transition:all .15s; }
  .attack-link:hover { color:var(--accent); border-bottom-color:var(--accent); }
  .attack-link::after { content:'\\2139'; color:var(--muted); margin-left:6px;
                        font-size:11px; opacity:.7; }
  .ip { font-family:Consolas,'Courier New',monospace; }
  .badge { padding:2px 9px; border-radius:20px; font-size:11px; font-weight:600; }
  .high   { background:rgba(248,81,73,.15);  color:var(--high); }
  .medium { background:rgba(210,153,34,.15); color:var(--med); }
  .low    { background:rgba(63,185,80,.15);  color:var(--low); }
  .risk { display:flex; align-items:center; gap:8px; min-width:90px; }
  .risk .bar { flex:1; height:6px; background:#0a0e14; border-radius:3px;
               overflow:hidden; border:1px solid var(--border); }
  .risk .fill { height:100%; transition:width .3s; }
  .risk .num { font-family:Consolas,monospace; font-size:12px; font-weight:600;
               min-width:28px; text-align:right; }
  .risk.r-crit .fill { background:var(--high); }
  .risk.r-high .fill { background:#f0883e; }
  .risk.r-med  .fill { background:var(--med); }
  .risk.r-low  .fill { background:var(--low); }
  .risk.r-crit .num { color:var(--high); }
  .risk.r-high .num { color:#f0883e; }
  .risk.r-med  .num { color:var(--med); }
  .risk.r-low  .num { color:var(--low); }
  .dir-inbound  { color:var(--high); }
  .dir-outbound { color:var(--accent); }
  .dir-local    { color:var(--muted); }
  .filters { margin-bottom:12px; }
  .filters button { background:var(--bg); color:var(--muted);
    border:1px solid var(--border); padding:5px 12px; border-radius:6px;
    cursor:pointer; font-size:12px; margin-right:6px; }
  .filters button.active { background:var(--accent); color:#fff;
    border-color:var(--accent); }
  .filters button.danger-btn { color:var(--high);
    border-color:rgba(248,81,73,.4); }
  .filters button.danger-btn:hover { background:var(--high); color:#fff;
    border-color:var(--high); }
  .modal-bg { position:fixed; inset:0; background:rgba(0,0,0,.65);
    display:none; align-items:center; justify-content:center; z-index:1000; }
  .modal-bg.show { display:flex; }
  .modal { background:var(--card); border:1px solid var(--border);
    border-radius:10px; padding:22px 26px; max-width:460px; width:90%;
    box-shadow:0 16px 48px rgba(0,0,0,.5); }
  .modal h2 { font-size:18px; color:var(--text); margin-bottom:10px; }
  .modal p { color:var(--muted); font-size:13.5px; line-height:1.55;
    margin-bottom:18px; }
  .modal p b { color:var(--text); }
  .modal-actions { display:flex; flex-wrap:wrap; gap:8px;
    justify-content:flex-end; align-items:center; }
  .modal-actions button, .modal-actions a {
    background:var(--bg); color:var(--text);
    border:1px solid var(--border); padding:8px 14px; border-radius:6px;
    cursor:pointer; font-size:13px; font-family:inherit;
    text-decoration:none; line-height:1.2; display:inline-block; }
  .modal-actions button:hover, .modal-actions a:hover {
    border-color:var(--accent); color:var(--accent); }
  .modal-actions .primary { background:var(--accent); color:#fff;
    border-color:var(--accent); }
  .modal-actions .primary:hover { background:#4090e0; color:#fff;
    border-color:#4090e0; }
  .modal-actions .danger { color:var(--high);
    border-color:rgba(248,81,73,.4); }
  .modal-actions .danger:hover { background:var(--high); color:#fff;
    border-color:var(--high); }
  .empty { color:var(--muted); text-align:center; padding:28px; }
  .alarm-btn { background:transparent; color:var(--muted);
    border:1px solid var(--border); padding:2px 10px; border-radius:14px;
    cursor:pointer; font-size:12px; font-family:inherit; vertical-align:middle; }
  .alarm-btn:hover { color:var(--text); border-color:var(--accent); }
  .alarm-btn.on { background:var(--high); color:#fff; border-color:var(--high); }
  .alarm-btn.on:hover { color:#fff; }
</style>
</head>
<body>
  <h1>&#128737; Network IDS Dashboard</h1>
  <div class="sub"><span class="dot"></span>Live &middot; auto-refresh every 5s &middot;
       <span id="updated">connecting...</span> &middot;
       <button id="alarm-toggle" class="alarm-btn" title="Play a siren on every new alert">&#128680; Alarm: OFF</button> &middot;
       <a href="/topology" style="color:var(--accent);text-decoration:none;">Attack Topology Simulator &rarr;</a></div>

  <div class="cards" id="cards"></div>

  <div class="layout">
    <div class="panel">
      <h2>Detected Attacks</h2>
      <div class="filters" id="filters">
        <button data-f="all" class="active">All</button>
        <button data-f="inbound">Inbound</button>
        <button data-f="outbound">Outbound</button>
        <button data-f="high">High severity</button>
        <button id="reset-log" class="danger-btn" title="Clear threat_log.csv. A timestamped backup is saved first.">&#128465; Reset Log</button>
      </div>
      <table>
        <thead><tr>
          <th>Time</th><th>IP</th><th>Direction</th>
          <th>Type</th><th>Severity</th><th>Score</th><th>Risk</th>
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

  <div class="modal-bg" id="reset-modal">
    <div class="modal">
      <!-- Step 1: ask the user. -->
      <div id="reset-step-ask">
        <h2>Reset threat log</h2>
        <p>The current log has <b id="reset-count">0</b> detections.
           Save a copy before clearing? Saved logs open on a separate
           analysis page so you can review them later.</p>
        <div class="modal-actions">
          <button id="reset-cancel">Cancel</button>
          <button id="reset-discard" class="danger">&#128465; Discard &amp; Reset</button>
          <button id="reset-save" class="primary">&#128190; Save &amp; Analyze</button>
        </div>
      </div>
      <!-- Step 2: confirmation after a successful save (hidden by default). -->
      <div id="reset-step-done" style="display:none">
        <h2 style="color:var(--low)">&#9989; Log saved</h2>
        <p>Backup written to:<br>
           <b style="font-family:Consolas,monospace; word-break:break-all;"
              id="reset-backup-name"></b></p>
        <p style="font-size:12.5px">If a new tab didn't open automatically,
           click the button below to view the analysis.</p>
        <div class="modal-actions">
          <button id="reset-done">Done</button>
          <a id="reset-open-analysis" class="primary"
             href="#" target="_blank"
             style="text-decoration:none; display:inline-block;">
            &#128202; Open Analysis
          </a>
        </div>
      </div>
    </div>
  </div>

<script>
  let allAlerts = [], filter = 'all';

  // ---- Alarm sound ----------------------------------------------------
  // Plays a two-tone siren via Web Audio on every new alert. Off by
  // default because browsers block audio until the user clicks
  // something; the toggle below is that gesture and persists in
  // localStorage. lastSeenTs is the newest timestamp we've already
  // alarmed on, so we don't replay the historical log on first load.
  let alarmOn    = localStorage.getItem('ids-alarm') === '1';
  let lastSeenTs = null;
  let audioCtx   = null;

  function playSiren() {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return;
    if (!audioCtx) audioCtx = new AC();
    if (audioCtx.state === 'suspended') audioCtx.resume();

    const ctx  = audioCtx;
    const now  = ctx.currentTime;
    const osc  = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type   = 'square';
    // Two-tone siren: alternate 880Hz / 523Hz, three times.
    const tones = [880, 523, 880, 523, 880, 523];
    const dur   = 0.18;
    tones.forEach((f, i) => osc.frequency.setValueAtTime(f, now + i * dur));
    // Envelope: fade in/out so it doesn't click.
    gain.gain.setValueAtTime(0.0001, now);
    gain.gain.linearRampToValueAtTime(0.18, now + 0.015);
    gain.gain.setValueAtTime(0.18, now + tones.length * dur - 0.04);
    gain.gain.linearRampToValueAtTime(0.0001, now + tones.length * dur);
    osc.connect(gain).connect(ctx.destination);
    osc.start(now);
    osc.stop(now + tones.length * dur + 0.05);
  }

  function fireAlarm() {
    if (!alarmOn) return;
    try { playSiren(); } catch (_) { /* best-effort */ }
  }

  function updateAlarmBtn() {
    const btn = document.getElementById('alarm-toggle');
    btn.classList.toggle('on', alarmOn);
    btn.innerHTML = alarmOn ? '&#128680; Alarm: ON' : '&#128680; Alarm: OFF';
  }

  document.getElementById('alarm-toggle').onclick = () => {
    alarmOn = !alarmOn;
    localStorage.setItem('ids-alarm', alarmOn ? '1' : '0');
    updateAlarmBtn();
    // Play a short test chirp on enable - also primes the browser's
    // autoplay gate so later automatic alarms are allowed.
    if (alarmOn) playSiren();
  };
  updateAlarmBtn();

  function fmtTime(t) {
    if (!t) return '\\u2014';
    return t.replace('T', ' ').slice(0, 19);
  }

  function riskTier(r) {
    if (r >= 80) return 'crit';
    if (r >= 60) return 'high';
    if (r >= 35) return 'med';
    return 'low';
  }

  // Map a threat_type label to the key used by /info/<key>.
  function infoKey(threat_type) {
    const t = (threat_type || '').toLowerCase();
    if (t.includes('port scan'))           return 'portscan';
    if (t.includes('dos') || t.includes('flood')) return 'dos';
    if (t.includes('brute'))               return 'bruteforce';
    if (t.includes('malicious'))           return 'malicious-ip';
    return null;
  }

  function riskCell(r) {
    const tier = riskTier(r);
    return `<div class="risk r-${tier}">
              <div class="bar"><div class="fill" style="width:${r}%"></div></div>
              <div class="num">${r}</div>
            </div>`;
  }

  function render() {
    let data = allAlerts;
    if (filter === 'inbound')  data = data.filter(a => a.direction === 'inbound');
    if (filter === 'outbound') data = data.filter(a => a.direction === 'outbound');
    if (filter === 'high')     data = data.filter(a => a.severity === 'high');

    const rows = document.getElementById('rows');
    if (!data.length) {
      rows.innerHTML = '<tr><td colspan="7" class="empty">No attacks detected yet.</td></tr>';
      return;
    }
    rows.innerHTML = data.map((a, i) => {
      const key = infoKey(a.threat_type);
      const typeCell = key
        ? `<a class="attack-link" data-key="${key}" title="Learn about this attack">${a.threat_type}</a>`
        : a.threat_type;
      return `
      <tr class="clickable" data-i="${i}" title="Click row to simulate this attack on the topology">
        <td>${fmtTime(a.timestamp)}</td>
        <td class="ip">${a.ip}</td>
        <td class="dir-${a.direction}">${a.direction}</td>
        <td>${typeCell}</td>
        <td><span class="badge ${a.severity}">${a.severity}</span></td>
        <td>${a.score}</td>
        <td>${riskCell(a.risk || 0)}</td>
      </tr>`;
    }).join('');

    // Type-cell link: open the awareness page in a new tab, don't trigger
    // the row-click handler.
    rows.querySelectorAll('.attack-link').forEach(a => {
      a.onclick = (e) => {
        e.stopPropagation();
        window.open('/info/' + a.dataset.key, '_blank');
      };
    });

    // Wire each row to open the topology page and auto-play this alert.
    rows.querySelectorAll('tr.clickable').forEach(tr => {
      tr.onclick = () => {
        const a = data[parseInt(tr.dataset.i, 10)];
        const params = new URLSearchParams({
          play:        '1',
          ip:          a.ip || '',
          threat_type: a.threat_type || '',
          direction:   a.direction || '',
          severity:    a.severity || '',
          score:       String(a.score || 0),
          risk:        String(a.risk || 0),
          description: a.description || '',
          timestamp:   a.timestamp || ''
        });
        window.location.href = '/topology?' + params.toString();
      };
    });
  }

  async function refresh() {
    try {
      const res = await fetch('/api/data');
      const d = await res.json();
      allAlerts = d.alerts;

      // Sound the alarm if any alert is newer than the last one we saw.
      // One siren per refresh cycle even if several arrived together.
      if (allAlerts.length) {
        const newest = allAlerts[0].timestamp;
        if (lastSeenTs === null) {
          lastSeenTs = newest;       // first load - just record baseline
        } else if (newest > lastSeenTs) {
          fireAlarm();
          lastSeenTs = newest;
        }
      }

      const s = d.stats;
      const maxRiskTier = riskTier(s.max_risk || 0);
      const maxRiskColor = {crit:'var(--high)', high:'#f0883e',
                            med:'var(--med)', low:'var(--low)'}[maxRiskTier];
      document.getElementById('cards').innerHTML = [
        ['Total alerts',     s.total,           null],
        ['Unique attackers', s.unique_ips,      null],
        ['Inbound',          s.inbound,         null],
        ['Outbound',         s.outbound,        null],
        ['High severity',    s.high,            null],
        ['Max risk',         s.max_risk || 0,   maxRiskColor],
        ['Avg risk',         s.avg_risk || 0,   null],
        ['Last alert',       fmtTime(s.last),   null]
      ].map(([l, v, c]) =>
        `<div class="card"><div class="label">${l}</div>
         <div class="value"${c?` style="color:${c}"`:''}>${v}</div></div>`).join('');

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

  document.querySelectorAll('#filters button:not(#reset-log)').forEach(b => {
    b.onclick = () => {
      document.querySelectorAll('#filters button:not(#reset-log)')
        .forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      filter = b.dataset.f;
      render();
    };
  });

  // ---- Reset-log modal -------------------------------------------------
  // Two-step flow:
  //   1. ASK: cancel / discard-without-saving / save-then-analyze.
  //   2. DONE (only after Save succeeds): show the backup filename and a
  //      direct link to the analysis page. We also try to auto-open it in
  //      a new tab, but popup blockers can silently drop that - the
  //      explicit link is the guaranteed escape hatch.
  const resetModal = document.getElementById('reset-modal');
  const stepAsk    = document.getElementById('reset-step-ask');
  const stepDone   = document.getElementById('reset-step-done');

  function showAskStep()  { stepAsk.style.display = '';   stepDone.style.display = 'none'; }
  function showDoneStep() { stepAsk.style.display = 'none'; stepDone.style.display = ''; }

  function openResetModal() {
    document.getElementById('reset-count').textContent = allAlerts.length;
    showAskStep();
    resetModal.classList.add('show');
  }
  function closeResetModal() {
    resetModal.classList.remove('show');
    // Reset to the question state so the next open starts fresh.
    showAskStep();
  }

  async function doReset(save, openTab) {
    try {
      const res = await fetch('/api/reset-log', {
        method:  'POST',
        headers: {'Content-Type': 'application/json'},
        body:    JSON.stringify({ save: save })
      });
      const d = await res.json();
      if (!d.ok) {
        if (openTab) openTab.close();
        alert('Reset failed: ' + (d.error || 'unknown error'));
        return;
      }

      // Don't reset lastSeenTs - leaving it at the old (now-deleted)
      // timestamp ensures the next real alert still fires the alarm.
      await refresh();

      if (save && d.backup) {
        const url = '/analyze/' + encodeURIComponent(d.backup);
        // Best-effort auto-open; if blocked, the user clicks the link below.
        if (openTab && !openTab.closed) {
          try { openTab.location.href = url; } catch (_) {}
        }
        document.getElementById('reset-backup-name').textContent = d.backup;
        document.getElementById('reset-open-analysis').href = url;
        showDoneStep();
      } else {
        // Discard path - just close.
        closeResetModal();
      }
    } catch (e) {
      if (openTab) openTab.close();
      alert('Reset failed: ' + e.message);
    }
  }

  document.getElementById('reset-log').onclick     = openResetModal;
  document.getElementById('reset-cancel').onclick  = closeResetModal;
  document.getElementById('reset-done').onclick    = closeResetModal;
  document.getElementById('reset-discard').onclick = () => doReset(false, null);
  document.getElementById('reset-save').onclick    = () => {
    // Open synchronously in the click handler so popup blockers allow it
    // when they can. If they still block, the success-step link is the
    // guaranteed fallback.
    let tab = null;
    try { tab = window.open('about:blank', '_blank'); } catch (_) {}
    doReset(true, tab);
  };
  // Click outside the box, or press Escape, to dismiss (only on the ask step).
  resetModal.onclick = (e) => {
    if (e.target === resetModal && stepAsk.style.display !== 'none') closeResetModal();
  };
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && resetModal.classList.contains('show')) closeResetModal();
  });

  refresh();
  setInterval(refresh, 5000);
</script>
</body>
</html>
"""


TOPOLOGY_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IDS - Attack Topology Simulator</title>
<style>
  :root {
    --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3;
    --muted:#8b949e; --high:#f85149; --med:#d29922; --low:#3fb950;
    --accent:#58a6ff; --wire:#3a4250;
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text);
         font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif; padding:24px; }
  h1 { font-size:21px; }
  .sub { color:var(--muted); font-size:13px; margin:4px 0 20px; }
  .sub a { color:var(--accent); text-decoration:none; }
  .layout { display:grid; grid-template-columns:3fr 1fr; gap:18px; }
  @media (max-width:1024px){ .layout{ grid-template-columns:1fr; } }
  .panel { background:var(--card); border:1px solid var(--border);
           border-radius:10px; padding:16px; }
  .panel h2 { font-size:13px; color:var(--muted); text-transform:uppercase;
              letter-spacing:.6px; margin-bottom:12px; }
  svg { width:100%; height:auto; display:block; background:#0a0e14;
        border-radius:8px; }
  .node-box { fill:#1f2630; stroke:var(--border); stroke-width:1.5; rx:8; }
  .node-box.active { stroke:var(--accent); stroke-width:2.5; }
  .node-box.alert  { stroke:var(--high);  stroke-width:3;
                     filter:drop-shadow(0 0 8px var(--high)); }
  .node-box.target { stroke:var(--med);   stroke-width:2.5;
                     filter:drop-shadow(0 0 6px var(--med)); }
  .node-label { fill:var(--text); font-size:13px; font-weight:600;
                text-anchor:middle; font-family:inherit;
                pointer-events:none; }
  .node-sub   { fill:var(--muted); font-size:10px; text-anchor:middle;
                font-family:Consolas,monospace; pointer-events:none; }
  .wire { stroke:var(--wire); stroke-width:2; fill:none; }
  .wire.mirror { stroke-dasharray:4 4; stroke:var(--muted); }
  .pkt { r:5; }
  .pkt.scan   { fill:var(--accent); }
  .pkt.dos    { fill:var(--high); }
  .pkt.brute  { fill:var(--med); }
  .pkt.mirror { opacity:.55; }
  .controls { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:14px; }
  .controls button { background:var(--bg); color:var(--text);
    border:1px solid var(--border); padding:8px 14px; border-radius:6px;
    cursor:pointer; font-size:13px; transition:all .15s; }
  .controls button:hover { border-color:var(--accent); color:var(--accent); }
  .controls button.danger:hover { border-color:var(--high); color:var(--high); }
  .controls button.warn:hover   { border-color:var(--med);  color:var(--med); }
  .controls button.live         { border-color:var(--low); color:var(--low); }
  .controls button.live.on      { background:var(--low); color:#0a0e14;
                                   border-color:var(--low);
                                   box-shadow:0 0 10px rgba(63,185,80,.5); }
  .controls button:disabled { opacity:.4; cursor:not-allowed; }
  .legend { display:flex; gap:14px; flex-wrap:wrap; font-size:12px;
            color:var(--muted); margin-top:10px; }
  .legend span { display:flex; align-items:center; gap:6px; }
  .legend i { width:10px; height:10px; border-radius:50%; display:inline-block; }
  .log { font-family:Consolas,monospace; font-size:12px;
         height:430px; overflow-y:auto; padding-right:4px; }
  .log .entry { padding:6px 8px; margin-bottom:4px; border-radius:4px;
                background:#0a0e14; border-left:3px solid var(--wire);
                white-space:pre-wrap; word-break:break-word; }
  .log .entry.info  { border-left-color:var(--accent); }
  .log .entry.alert { border-left-color:var(--high);
                      background:rgba(248,81,73,.08); }
  .log .t { color:var(--muted); margin-right:6px; }
  .stats { display:grid; grid-template-columns:1fr 1fr; gap:8px;
           margin-bottom:12px; }
  .stat { background:#0a0e14; border:1px solid var(--border);
          border-radius:6px; padding:8px; text-align:center; }
  .stat .v { font-size:18px; font-weight:600; }
  .stat .l { font-size:10px; color:var(--muted); text-transform:uppercase;
             letter-spacing:.5px; margin-top:2px; }
</style>
</head>
<body>
  <h1>&#127760; Attack Topology Simulator</h1>
  <div class="sub">Visualises how the IDS sees a port scan, DoS flood, and
       brute-force attempt traversing the network &middot;
       <a href="/">&larr; back to Dashboard</a></div>

  <div class="layout">
    <div class="panel">
      <div class="controls">
        <button id="btn-live"  class="live">&#128225; Live IDS Feed: OFF</button>
        <button id="btn-scan"  class="warn">&#128269; Demo Port Scan</button>
        <button id="btn-dos"   class="danger">&#128165; Demo DoS</button>
        <button id="btn-brute" class="warn">&#128274; Demo Brute Force</button>
        <button id="btn-stop">&#9632; Stop Demo</button>
        <button id="btn-clear">Clear Log</button>
      </div>

      <svg id="topo" viewBox="0 0 1000 520" preserveAspectRatio="xMidYMid meet">
        <!-- wires -->
        <line class="wire" x1="160" y1="260" x2="290" y2="260"/>
        <line class="wire" x1="410" y1="260" x2="560" y2="260"/>
        <line class="wire mirror" x1="485" y1="260" x2="485" y2="160"/>
        <line class="wire" x1="680" y1="260" x2="820" y2="120"/>
        <line class="wire" x1="680" y1="260" x2="830" y2="260"/>
        <line class="wire" x1="680" y1="260" x2="820" y2="400"/>

        <!-- attacker -->
        <g id="n-attacker">
          <rect class="node-box" x="40"  y="225" width="120" height="70"/>
          <text class="node-label" x="100" y="255">Attacker</text>
          <text class="node-sub"   x="100" y="275">203.0.113.66</text>
          <text class="node-sub"   x="100" y="288">(external)</text>
        </g>

        <!-- router/firewall -->
        <g id="n-router">
          <rect class="node-box" x="290" y="230" width="120" height="60"/>
          <text class="node-label" x="350" y="255">Router / FW</text>
          <text class="node-sub"   x="350" y="275">192.168.1.1</text>
        </g>

        <!-- IDS sensor (port mirror) -->
        <g id="n-ids">
          <rect class="node-box" x="425" y="90" width="120" height="70"/>
          <text class="node-label" x="485" y="120">IDS Sensor</text>
          <text class="node-sub"   x="485" y="138">port mirror</text>
          <text class="node-sub" id="ids-state" x="485" y="151">idle</text>
        </g>

        <!-- switch -->
        <g id="n-switch">
          <rect class="node-box" x="560" y="230" width="120" height="60"/>
          <text class="node-label" x="620" y="255">Switch</text>
          <text class="node-sub"   x="620" y="275">LAN core</text>
        </g>

        <!-- web server -->
        <g id="n-web">
          <rect class="node-box" x="820" y="80"  width="140" height="70"/>
          <text class="node-label" x="890" y="110">Web Server</text>
          <text class="node-sub"   x="890" y="128">192.168.1.10:80</text>
          <text class="node-sub"   x="890" y="141">nginx</text>
        </g>

        <!-- database / ssh -->
        <g id="n-db">
          <rect class="node-box" x="820" y="225" width="140" height="70"/>
          <text class="node-label" x="890" y="255">SSH / DB Host</text>
          <text class="node-sub"   x="890" y="273">192.168.1.20:22</text>
          <text class="node-sub"   x="890" y="286">login service</text>
        </g>

        <!-- workstation -->
        <g id="n-pc">
          <rect class="node-box" x="820" y="365" width="140" height="70"/>
          <text class="node-label" x="890" y="395">Workstation</text>
          <text class="node-sub"   x="890" y="413">192.168.1.50</text>
          <text class="node-sub"   x="890" y="426">user PC</text>
        </g>

        <!-- packets get appended here at runtime -->
        <g id="packets"></g>
      </svg>

      <div class="legend">
        <span><i style="background:#58a6ff"></i>Port scan packet</span>
        <span><i style="background:#f85149"></i>DoS / SYN flood</span>
        <span><i style="background:#d29922"></i>Brute-force attempt</span>
        <span><i style="background:#8b949e;opacity:.55"></i>Mirror copy to IDS</span>
      </div>
    </div>

    <div class="panel">
      <h2>Live Simulation</h2>
      <div class="stats">
        <div class="stat"><div class="v" id="s-pkts">0</div><div class="l">Packets sent</div></div>
        <div class="stat"><div class="v" id="s-alerts">0</div><div class="l">IDS alerts</div></div>
        <div class="stat" style="grid-column:span 2;">
          <div class="v" id="s-live">0</div>
          <div class="l">Live alerts from IDS log</div>
        </div>
      </div>
      <h2>Event Log</h2>
      <div class="log" id="log">
        <div class="entry info"><span class="t">--:--:--</span>Idle. Pick an attack to simulate.</div>
      </div>
    </div>
  </div>

<script>
  // ---- Network topology -------------------------------------------------
  // Coordinates are anchor points on each node where packets enter/leave.
  const POS = {
    attacker: { x:160, y:260 },
    router:   { x:290, y:260, exit:{x:410,y:260} },
    tap:      { x:485, y:260 },           // port-mirror tap point
    ids:      { x:485, y:160 },
    switch:   { x:560, y:260, exit:{x:680,y:260} },
    web:      { x:820, y:120 },
    db:       { x:830, y:260 },
    pc:       { x:820, y:400 }
  };

  // Detection thresholds (mirror what detectors.py uses, but scaled for a
  // visualisation that finishes in a few seconds).
  const THRESH = { scan: 15, dos: 25, brute: 10 };

  // ---- State ------------------------------------------------------------
  const svg = document.getElementById('topo');
  const packetsLayer = document.getElementById('packets');
  const idsState = document.getElementById('ids-state');
  const SVG_NS = 'http://www.w3.org/2000/svg';

  let currentAttack = null;     // 'scan' | 'dos' | 'brute' | null
  let spawnTimer    = null;
  let packetCount   = 0;
  let attackPackets = 0;        // packets in the current attack window
  let alertCount    = 0;
  let raf           = null;
  const flying      = new Set();// active packet objects
  let topoAudioCtx  = null;

  // Two-tone siren via Web Audio. Matches the one on the main dashboard
  // so the experience is consistent.
  function topoSiren() {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return;
    if (!topoAudioCtx) topoAudioCtx = new AC();
    if (topoAudioCtx.state === 'suspended') topoAudioCtx.resume();
    const ctx  = topoAudioCtx;
    const now  = ctx.currentTime;
    const osc  = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type   = 'square';
    const tones = [880, 523, 880, 523, 880, 523];
    const dur   = 0.18;
    tones.forEach((f, i) => osc.frequency.setValueAtTime(f, now + i * dur));
    gain.gain.setValueAtTime(0.0001, now);
    gain.gain.linearRampToValueAtTime(0.18, now + 0.015);
    gain.gain.setValueAtTime(0.18, now + tones.length * dur - 0.04);
    gain.gain.linearRampToValueAtTime(0.0001, now + tones.length * dur);
    osc.connect(gain).connect(ctx.destination);
    osc.start(now);
    osc.stop(now + tones.length * dur + 0.05);
  }

  // ---- Helpers ----------------------------------------------------------
  function $(id) { return document.getElementById(id); }

  function setNodeState(nodeId, state) {
    const box = document.querySelector(`#${nodeId} rect`);
    box.classList.remove('active', 'alert', 'target');
    if (state) box.classList.add(state);
  }

  function pulseTarget(nodeId, ms=600) {
    setNodeState(nodeId, 'target');
    setTimeout(() => setNodeState(nodeId, null), ms);
  }

  function logLine(msg, type='info') {
    const log = $('log');
    const e = document.createElement('div');
    e.className = 'entry ' + type;
    const t = new Date().toLocaleTimeString();
    e.innerHTML = `<span class="t">${t}</span>${msg}`;
    log.insertBefore(e, log.firstChild);
    // cap to 100 entries
    while (log.children.length > 100) log.removeChild(log.lastChild);
  }

  function spawnPacket(path, kind, opts={}) {
    const c = document.createElementNS(SVG_NS, 'circle');
    c.setAttribute('class', 'pkt ' + kind + (opts.mirror ? ' mirror' : ''));
    c.setAttribute('cx', path[0].x);
    c.setAttribute('cy', path[0].y);
    packetsLayer.appendChild(c);

    const pkt = {
      el: c, path, kind,
      onArrive: opts.onArrive || null,
      seg: 0,
      t: 0,
      speed: opts.speed || 0.045,    // segments-per-frame at 60fps-ish
    };
    flying.add(pkt);
    return pkt;
  }

  function step() {
    for (const p of [...flying]) {
      p.t += p.speed;
      while (p.t >= 1 && p.seg < p.path.length - 1) {
        p.t -= 1;
        p.seg += 1;
      }
      if (p.seg >= p.path.length - 1) {
        const last = p.path[p.path.length - 1];
        p.el.setAttribute('cx', last.x);
        p.el.setAttribute('cy', last.y);
        p.el.remove();
        flying.delete(p);
        if (p.onArrive) p.onArrive();
        continue;
      }
      const a = p.path[p.seg], b = p.path[p.seg + 1];
      p.el.setAttribute('cx', a.x + (b.x - a.x) * p.t);
      p.el.setAttribute('cy', a.y + (b.y - a.y) * p.t);
    }
    raf = requestAnimationFrame(step);
  }

  // ---- Attack scenarios -------------------------------------------------
  // Each attack spawns one main packet on a path Attacker -> Router -> Tap
  // -> Switch -> Target, plus a mirror copy that branches at the tap up to
  // the IDS sensor.
  const TARGETS = {
    scan:  ['web','db','pc','web','db','pc'],   // fan-out across ports/hosts
    dos:   ['web'],                              // single victim
    brute: ['db']                                // SSH brute force
  };

  function attackTrigger(kind) {
    const labels = {
      scan:  'Port scan',
      dos:   'DoS / SYN flood',
      brute: 'Brute-force login attempt'
    };
    const target = TARGETS[kind][attackPackets % TARGETS[kind].length];
    const targetNode = { web:'n-web', db:'n-db', pc:'n-pc' }[target];

    // Main path: attacker -> router -> tap -> switch -> target
    const mainPath = [
      POS.attacker,
      POS.router,
      POS.router.exit,
      POS.tap,
      POS.switch,
      POS.switch.exit,
      POS[target]
    ];

    spawnPacket(mainPath, kind, {
      onArrive: () => { pulseTarget(targetNode); }
    });

    // Mirror copy: tap -> IDS (starts at the tap when the main packet hits)
    // We start it slightly later so they visually diverge at the tap.
    setTimeout(() => {
      spawnPacket([POS.tap, POS.ids], kind, {
        mirror: true,
        speed: 0.06,
        onArrive: () => { setNodeState('n-ids', 'active');
                          setTimeout(() => {
                            if (!flying.size) setNodeState('n-ids', null);
                          }, 350); }
      });
    }, 480);

    packetCount   += 1;
    attackPackets += 1;
    $('s-pkts').textContent = packetCount;

    // Threshold tripped -> raise an IDS alert (matches detectors.py logic).
    if (attackPackets === THRESH[kind]) {
      raiseAlert(kind, labels[kind]);
    } else if (attackPackets === 1) {
      idsState.textContent = 'inspecting';
      setNodeState('n-ids', 'active');
      logLine(`${labels[kind]} started from attacker 203.0.113.66`, 'info');
    }
  }

  function raiseAlert(kind, label) {
    alertCount += 1;
    $('s-alerts').textContent = alertCount;
    setNodeState('n-ids', 'alert');
    idsState.textContent = 'ALERT';
    const detail = {
      scan:  `${THRESH.scan} distinct ports/hosts probed in window`,
      dos:   `${THRESH.dos} packets to single victim - flood detected`,
      brute: `${THRESH.brute} failed login attempts on SSH (port 22)`
    }[kind];
    logLine(`[ALERT] ${label} from 203.0.113.66 - ${detail}`, 'alert');
  }

  function startAttack(kind) {
    stopAttack();
    currentAttack = kind;
    attackPackets = 0;
    setNodeState('n-attacker', 'active');
    const cadence = { scan:240, dos:90, brute:400 }[kind];
    attackTrigger(kind);
    spawnTimer = setInterval(() => attackTrigger(kind), cadence);
  }

  function stopAttack() {
    if (spawnTimer) clearInterval(spawnTimer);
    spawnTimer = null;
    currentAttack = null;
    setNodeState('n-attacker', null);
    setTimeout(() => {
      setNodeState('n-ids', null);
      idsState.textContent = 'idle';
    }, 800);
  }

  // ---- Live feed from threat_log.csv -----------------------------------
  // Polls /api/topology-feed, then replays each new alert as a packet burst
  // on the topology. The first call just captures the server "now" so we
  // don't animate the entire historical log.
  let liveOn      = false;
  let liveSince   = '';
  let livePoll    = null;
  let liveCount   = 0;
  let liveQueue   = [];

  // Map an IDS threat_type string to (animation kind, packet count, target).
  function mapAlert(threat_type, direction) {
    const t = (threat_type || '').toLowerCase();
    if (t.includes('port scan'))   return { kind:'scan',  burst:6, target:null };
    if (t.includes('syn flood'))   return { kind:'dos',   burst:10, target:'web' };
    if (t.includes('packet flood'))return { kind:'dos',   burst:10, target:'web' };
    if (t.includes('brute'))       return { kind:'brute', burst:5,  target:'db' };
    if (t.includes('malicious'))   return { kind:'rep',
                                             burst:2,
                                             target: direction === 'outbound' ? null : 'pc',
                                             outbound: direction === 'outbound' };
    return { kind:'scan', burst:3, target:null };
  }

  function playLiveAlert(alert) {
    const m = (alert.threat_type || '').toLowerCase().includes('malicious')
              ? mapAlert(alert.threat_type, alert.direction)
              : mapAlert(alert.threat_type, 'inbound');
    const labels = {
      scan:'Port scan', dos:'DoS / flood', brute:'Brute force', rep:'Malicious IP'
    };
    const label = labels[m.kind] || alert.threat_type;
    const fanOut = ['web','db','pc'];

    const riskTxt = (alert.risk !== undefined && alert.risk !== null)
                    ? ` | risk ${alert.risk}/100` : '';
    logLine(`[LIVE] ${label} - ${alert.ip} (${alert.severity}, score ${alert.score}${riskTxt})`,
            'info');

    let i = 0;
    const fire = () => {
      const target = m.target || fanOut[i % fanOut.length];
      const targetId = { web:'n-web', db:'n-db', pc:'n-pc' }[target];

      let path;
      if (m.outbound) {
        // Outbound: internal host -> switch -> tap -> router -> attacker (the
        // remote malicious IP, drawn at the attacker node position).
        path = [
          POS[target], POS.switch.exit, POS.switch, POS.tap,
          POS.router.exit, POS.router, POS.attacker
        ];
      } else {
        path = [
          POS.attacker, POS.router, POS.router.exit, POS.tap,
          POS.switch, POS.switch.exit, POS[target]
        ];
      }

      spawnPacket(path, m.kind, {
        onArrive: () => { if (!m.outbound) pulseTarget(targetId); }
      });
      // Mirror to IDS
      setTimeout(() => {
        spawnPacket([POS.tap, POS.ids], m.kind, {
          mirror:true, speed:0.06,
          onArrive: () => setNodeState('n-ids', 'active')
        });
      }, 480);

      packetCount += 1;
      $('s-pkts').textContent = packetCount;
      setNodeState('n-attacker', 'active');

      i += 1;
      if (i < m.burst) {
        setTimeout(fire, 180);
      } else {
        // Burst done -> raise IDS alert
        setTimeout(() => {
          alertCount += 1;
          liveCount  += 1;
          $('s-alerts').textContent = alertCount;
          $('s-live').textContent   = liveCount;
          setNodeState('n-ids', 'alert');
          idsState.textContent = 'ALERT';
          logLine(`[ALERT] ${alert.threat_type} from ${alert.ip} - ${alert.description || ''}`,
                  'alert');
          // Respect the dashboard's alarm toggle (shared via localStorage).
          if (localStorage.getItem('ids-alarm') === '1') {
            try { topoSiren(); } catch (_) {}
          }
          setTimeout(() => {
            setNodeState('n-attacker', null);
            setNodeState('n-ids', null);
            idsState.textContent = liveOn ? 'live' : 'idle';
            // Pull the next queued alert, if any.
            const next = liveQueue.shift();
            if (next) playLiveAlert(next);
          }, 1100);
        }, 600);
      }
    };
    fire();
  }

  async function pollLive() {
    try {
      const url = '/api/topology-feed' + (liveSince ? '?since=' + encodeURIComponent(liveSince) : '');
      const res = await fetch(url);
      const d   = await res.json();
      liveSince = d.now || liveSince;
      if (d.alerts && d.alerts.length) {
        // If nothing currently playing, start immediately; else queue.
        const stillPlaying = flying.size > 0;
        for (const a of d.alerts) {
          if (!stillPlaying && liveQueue.length === 0) {
            playLiveAlert(a);
          } else {
            liveQueue.push(a);
          }
        }
      }
    } catch (e) {
      logLine('Live feed error: ' + e.message, 'alert');
    }
  }

  function setLive(on) {
    liveOn = on;
    const btn = $('btn-live');
    btn.classList.toggle('on', on);
    btn.innerHTML = (on ? '&#128225; Live IDS Feed: ON' : '&#128225; Live IDS Feed: OFF');
    if (on) {
      idsState.textContent = 'live';
      logLine('Live feed connected - watching threat_log.csv for new alerts.', 'info');
      // Bootstrap: get current server time, then start polling.
      fetch('/api/topology-feed').then(r => r.json()).then(d => {
        liveSince = d.now || '';
        livePoll = setInterval(pollLive, 1500);
      });
    } else {
      if (livePoll) clearInterval(livePoll);
      livePoll = null;
      idsState.textContent = 'idle';
      logLine('Live feed stopped.', 'info');
    }
  }

  // ---- Wire up UI -------------------------------------------------------
  $('btn-live').onclick  = () => setLive(!liveOn);
  $('btn-scan').onclick  = () => startAttack('scan');
  $('btn-dos').onclick   = () => startAttack('dos');
  $('btn-brute').onclick = () => startAttack('brute');
  $('btn-stop').onclick  = () => { stopAttack();
                                   logLine('Demo stopped.', 'info'); };
  $('btn-clear').onclick = () => {
    $('log').innerHTML = '';
    packetCount = alertCount = liveCount = 0;
    $('s-pkts').textContent = 0;
    $('s-alerts').textContent = 0;
    $('s-live').textContent = 0;
  };

  step();   // start the animation loop

  // ---- Auto-play from URL params ----------------------------------------
  // The main dashboard links here with ?play=1&ip=...&threat_type=... when
  // a row is clicked, so the user immediately sees that alert simulated.
  (function autoplayFromUrl() {
    const q = new URLSearchParams(window.location.search);
    if (q.get('play') !== '1') return;
    const alert = {
      ip:          q.get('ip')          || 'unknown',
      threat_type: q.get('threat_type') || '',
      direction:   q.get('direction')   || 'inbound',
      severity:    q.get('severity')    || 'medium',
      score:       parseInt(q.get('score') || '0', 10),
      risk:        parseInt(q.get('risk')  || '0', 10),
      description: q.get('description') || '',
      timestamp:   q.get('timestamp')   || ''
    };
    logLine(`Replaying alert from dashboard: ${alert.threat_type} - ${alert.ip}`, 'info');
    // Small delay so the SVG and styles have rendered.
    setTimeout(() => playLiveAlert(alert), 350);
  })();
</script>
</body>
</html>
"""


ANALYZE_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Archived Log Analysis</title>
<style>
  :root {
    --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3;
    --muted:#8b949e; --high:#f85149; --med:#d29922; --low:#3fb950; --accent:#58a6ff;
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text);
         font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif; padding:24px; }
  .crumb { color:var(--muted); font-size:13px; margin-bottom:16px; }
  .crumb a { color:var(--accent); text-decoration:none; }
  .crumb a:hover { text-decoration:underline; }
  h1 { font-size:22px; }
  .sub { color:var(--muted); font-size:13px; margin:4px 0 20px;
         font-family:Consolas,'Courier New',monospace; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
           gap:14px; margin-bottom:22px; }
  .card { background:var(--card); border:1px solid var(--border);
          border-radius:10px; padding:16px; }
  .card .label { color:var(--muted); font-size:11px; text-transform:uppercase;
                 letter-spacing:.6px; }
  .card .value { font-size:24px; font-weight:600; margin-top:6px;
                 word-break:break-word; }
  .layout { display:grid; grid-template-columns:2fr 1fr; gap:18px; }
  @media (max-width:880px){ .layout{ grid-template-columns:1fr; } }
  .panel { background:var(--card); border:1px solid var(--border);
           border-radius:10px; padding:16px; margin-bottom:18px; }
  .panel h2 { font-size:13px; color:var(--muted); text-transform:uppercase;
              letter-spacing:.6px; margin-bottom:12px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th { text-align:left; color:var(--muted); font-weight:500; padding:8px;
       border-bottom:1px solid var(--border); position:sticky; top:0;
       background:var(--card); z-index:1; }
  td { padding:8px; border-bottom:1px solid var(--border);
       vertical-align:top; }
  tr:last-child td { border-bottom:none; }
  .ip { font-family:Consolas,'Courier New',monospace; }
  .badge { padding:2px 9px; border-radius:20px; font-size:11px; font-weight:600; }
  .high   { background:rgba(248,81,73,.15);  color:var(--high); }
  .medium { background:rgba(210,153,34,.15); color:var(--med); }
  .low    { background:rgba(63,185,80,.15);  color:var(--low); }
  .risk { display:flex; align-items:center; gap:8px; min-width:90px; }
  .risk .bar { flex:1; height:6px; background:#0a0e14; border-radius:3px;
               overflow:hidden; border:1px solid var(--border); }
  .risk .fill { height:100%; }
  .risk .num { font-family:Consolas,monospace; font-size:12px; font-weight:600;
               min-width:28px; text-align:right; }
  .risk.r-crit .fill { background:var(--high); }
  .risk.r-high .fill { background:#f0883e; }
  .risk.r-med  .fill { background:var(--med); }
  .risk.r-low  .fill { background:var(--low); }
  .risk.r-crit .num { color:var(--high); }
  .risk.r-high .num { color:#f0883e; }
  .risk.r-med  .num { color:var(--med); }
  .risk.r-low  .num { color:var(--low); }
  .dir-inbound  { color:var(--high); }
  .dir-outbound { color:var(--accent); }
  .dir-local    { color:var(--muted); }
  .table-wrap { max-height:540px; overflow-y:auto; }
  .empty { color:var(--muted); text-align:center; padding:28px; }
  .desc { color:var(--muted); font-size:12px; max-width:340px;
          white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .breakdown { display:flex; flex-direction:column; gap:8px; }
  .br-row { display:grid; grid-template-columns:1fr auto; align-items:center;
            gap:8px; }
  .br-row .lbl { font-size:13px; color:var(--text); }
  .br-row .cnt { font-family:Consolas,monospace; font-size:12px;
                 color:var(--muted); }
  .br-bar { grid-column:1 / -1; height:4px; background:#0a0e14;
            border-radius:2px; overflow:hidden;
            border:1px solid var(--border); }
  .br-fill { height:100%; background:var(--accent); }
  .br-fill.high { background:var(--high); }
  .br-fill.med  { background:var(--med); }
  .meta-line { color:var(--muted); font-size:12px; margin-top:14px; }
</style>
</head>
<body>
  <div class="crumb">
    <a href="/">&larr; Back to live dashboard</a>
  </div>

  <h1>&#128202; Archived Threat Log Analysis</h1>
  <div class="sub" id="meta">loading...</div>

  <div class="cards" id="cards"></div>

  <div class="layout">
    <div class="panel">
      <h2 id="table-title">All Detections</h2>
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th>Time</th><th>IP</th><th>Direction</th>
            <th>Type</th><th>Severity</th><th>Score</th>
            <th>Risk</th><th>Description</th>
          </tr></thead>
          <tbody id="rows"></tbody>
        </table>
      </div>
    </div>

    <div>
      <div class="panel">
        <h2>Threat Type Breakdown</h2>
        <div class="breakdown" id="by-type"></div>
      </div>
      <div class="panel">
        <h2>Top Attackers</h2>
        <table>
          <thead><tr><th>IP</th><th>Hits</th></tr></thead>
          <tbody id="top"></tbody>
        </table>
      </div>
      <div class="panel">
        <h2>Severity Mix</h2>
        <div class="breakdown" id="sev-mix"></div>
      </div>
    </div>
  </div>

<script>
  const data = __PAYLOAD__;

  function fmtTime(t) {
    if (!t) return '\\u2014';
    return t.replace('T', ' ').slice(0, 19);
  }

  function riskTier(r) {
    if (r >= 80) return 'crit';
    if (r >= 60) return 'high';
    if (r >= 35) return 'med';
    return 'low';
  }

  function riskCell(r) {
    const tier = riskTier(r);
    return `<div class="risk r-${tier}">
              <div class="bar"><div class="fill" style="width:${r}%"></div></div>
              <div class="num">${r}</div>
            </div>`;
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[c]));
  }

  // ---- Header / meta ----------------------------------------------------
  const span = (data.stats.first && data.stats.last)
    ? `${fmtTime(data.stats.first)}  \\u2192  ${fmtTime(data.stats.last)}`
    : 'no detections';
  document.getElementById('meta').textContent =
    `${data.filename}  \\u00B7  saved ${data.saved_at}  \\u00B7  ${data.stats.total} detections  \\u00B7  ${span}`;

  // ---- Cards ------------------------------------------------------------
  const s = data.stats;
  document.getElementById('cards').innerHTML = [
    ['Total alerts',     s.total,      null],
    ['Unique attackers', s.unique_ips, null],
    ['Inbound',          s.inbound,    'var(--high)'],
    ['Outbound',         s.outbound,   'var(--accent)'],
    ['High severity',    s.high,       'var(--high)'],
    ['Medium severity',  s.medium,     'var(--med)'],
    ['Low severity',     s.low,        'var(--low)'],
    ['Max risk',         s.max_risk,   null],
    ['Avg risk',         s.avg_risk,   null]
  ].map(([l, v, c]) =>
    `<div class="card"><div class="label">${l}</div>
     <div class="value"${c?` style="color:${c}"`:''}>${v}</div></div>`).join('');

  // ---- Detection table --------------------------------------------------
  const rows = document.getElementById('rows');
  if (!data.alerts.length) {
    rows.innerHTML = '<tr><td colspan="8" class="empty">No detections in this backup.</td></tr>';
  } else {
    rows.innerHTML = data.alerts.map(a => `
      <tr>
        <td>${fmtTime(a.timestamp)}</td>
        <td class="ip">${esc(a.ip)}</td>
        <td class="dir-${esc(a.direction)}">${esc(a.direction)}</td>
        <td>${esc(a.threat_type)}</td>
        <td><span class="badge ${esc(a.severity)}">${esc(a.severity)}</span></td>
        <td>${a.score}</td>
        <td>${riskCell(a.risk || 0)}</td>
        <td class="desc" title="${esc(a.description || '')}">${esc(a.description || '')}</td>
      </tr>`).join('');
  }
  document.getElementById('table-title').textContent =
    `All Detections (${data.alerts.length})`;

  // ---- Threat-type breakdown -------------------------------------------
  const byType = document.getElementById('by-type');
  if (!data.by_type.length) {
    byType.innerHTML = '<div class="empty">No data.</div>';
  } else {
    byType.innerHTML = data.by_type.map(t => `
      <div class="br-row"><span class="lbl">${esc(t.label)}</span>
        <span class="cnt">${t.count}</span>
        <div class="br-bar"><div class="br-fill" style="width:${t.pct}%"></div></div>
      </div>`).join('');
  }

  // ---- Top attackers ----------------------------------------------------
  const top = document.getElementById('top');
  top.innerHTML = data.top_attackers.length
    ? data.top_attackers.map(t =>
        `<tr><td class="ip">${esc(t.ip)}</td><td>${t.count}</td></tr>`).join('')
    : '<tr><td colspan="2" class="empty">No attackers in this backup.</td></tr>';

  // ---- Severity mix -----------------------------------------------------
  const sev = document.getElementById('sev-mix');
  const sevMax = Math.max(s.high, s.medium, s.low, 1);
  sev.innerHTML = [
    ['high',   s.high,   'high'],
    ['medium', s.medium, 'med'],
    ['low',    s.low,    '']
  ].map(([lbl, count, cls]) => {
    const pct = Math.round(100 * count / sevMax);
    return `<div class="br-row"><span class="lbl">${lbl}</span>
              <span class="cnt">${count}</span>
              <div class="br-bar"><div class="br-fill ${cls}" style="width:${pct}%"></div></div>
            </div>`;
  }).join('');
</script>
</body>
</html>
"""


INFO_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - IDS Awareness</title>
<style>
  :root {{
    --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3;
    --muted:#8b949e; --accent:#58a6ff;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text);
         font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
         padding:24px; max-width:1100px; margin:0 auto; }}
  .crumb {{ color:var(--muted); font-size:13px; margin-bottom:16px; }}
  .crumb a {{ color:var(--accent); text-decoration:none; }}
  .crumb a:hover {{ text-decoration:underline; }}
  .header {{ background:var(--card); border:1px solid var(--border);
             border-left:6px solid {color};
             border-radius:10px; padding:24px 28px; margin-bottom:22px; }}
  .header .icon {{ font-size:32px; margin-right:8px; }}
  .header h1 {{ display:inline-block; font-size:26px; vertical-align:middle; }}
  .header .tagline {{ color:{color}; font-size:14px; font-weight:500;
                      margin-top:8px; }}
  .header .summary {{ color:var(--text); font-size:14px; line-height:1.6;
                      margin-top:14px; max-width:80ch; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(380px,1fr));
           gap:16px; }}
  .info-panel {{ background:var(--card); border:1px solid var(--border);
                 border-radius:10px; padding:18px 22px; }}
  .info-panel h2 {{ font-size:14px; color:{color}; text-transform:uppercase;
                    letter-spacing:.6px; margin-bottom:14px;
                    border-bottom:1px solid var(--border); padding-bottom:8px; }}
  .info-panel ul {{ list-style:none; padding:0; }}
  .info-panel li {{ font-size:13.5px; line-height:1.65; color:var(--text);
                    padding:6px 0 6px 22px; position:relative; }}
  .info-panel li::before {{ content:'\\25B8'; color:{color}; position:absolute;
                            left:4px; top:6px; font-size:11px; }}
  .info-panel code {{ background:#0a0e14; border:1px solid var(--border);
                      padding:1px 6px; border-radius:4px; font-size:12px;
                      color:#e6c07b; font-family:Consolas,'Courier New',monospace; }}
  .info-panel b {{ color:{color}; }}
  .footer {{ color:var(--muted); font-size:12px; margin-top:24px;
             text-align:center; }}
  .footer a {{ color:var(--accent); text-decoration:none; }}
</style>
</head>
<body>
  <div class="crumb">
    <a href="/">&larr; Dashboard</a>
    &middot; <a href="/topology">Topology Simulator</a>
    &middot; <span>Attack details: {title}</span>
  </div>

  <div class="header">
    <span class="icon">{icon}</span>
    <h1>{title}</h1>
    <div class="tagline">{tagline}</div>
    <div class="summary">{summary}</div>
  </div>

  <div class="grid">
    {sections}
  </div>

  <div class="footer">
    Want to see this attack run in the topology?
    <a href="/topology">Open the simulator &rarr;</a>
  </div>
</body>
</html>
"""


if __name__ == "__main__":
    print(f"[*] IDS dashboard running at http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)
