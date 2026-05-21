"""
Alerting and logging.

Every detection is appended to threat_log.csv (the file the dashboard reads).
Repeat hits from the same IP within a short window are suppressed so the log
and the optional email alerts are not flooded by a single noisy host.
"""

import csv
import os
import time
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

LOG_FILE = "threat_log.csv"
LOG_HEADER = ["timestamp", "ip", "direction", "threat_type", "severity", "score", "description"]

# --- De-duplication -------------------------------------------------------
# Same IP + direction is logged at most once per ALERT_COOLDOWN seconds.
ALERT_COOLDOWN = 60
_last_alert = {}      # (ip, direction) -> epoch time of last alert
_last_behavior = {}   # (ip, attack_type) -> epoch time of last behavioral alert

# --- Email alerting (optional) --------------------------------------------
# Leave ENABLE_EMAIL = False until the SMTP settings below are filled in.
ENABLE_EMAIL = False
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "your_email@gmail.com"
SMTP_PASSWORD = "your_password"
ALERT_RECIPIENT = "alert_recipient@example.com"


def _severity(score):
    """Map an IPsum score to a severity label."""
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _ensure_log_header():
    """Write the CSV header if the log file is missing or empty."""
    if not os.path.isfile(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
        with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(LOG_HEADER)


def log_threat(ip, direction, threat_type, severity, score, description):
    """Append a single row to threat_log.csv (no cooldown, no email)."""
    _ensure_log_header()
    try:
        with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                datetime.now().isoformat(), ip, direction,
                threat_type, severity, score, description,
            ])
    except Exception as e:
        print(f"[ERROR] Failed to log alert: {e}")


def alert(ip, direction, score, interface=""):
    """
    Record an IDS detection.

    `direction` is "inbound" (malicious source) or "outbound" (malicious
    destination). Returns True if the event was recorded, False if it was
    suppressed because the same IP/direction was alerted on recently.
    """
    key = (ip, direction)
    now = time.time()
    if now - _last_alert.get(key, 0) < ALERT_COOLDOWN:
        return False
    _last_alert[key] = now

    severity = _severity(score)
    if direction == "inbound":
        threat_type = "Malicious source IP"
        description = f"Inbound traffic from known-malicious IP {ip}"
    else:
        threat_type = "Malicious destination IP"
        description = f"Outbound traffic to known-malicious IP {ip}"
    if interface:
        description += f" on interface {interface}"

    log_threat(ip, direction, threat_type, severity, score, description)

    if ENABLE_EMAIL:
        send_email_alert(ip, threat_type, severity, description)
    return True


def alert_behavior(ip, attack_type, severity, score, detail):
    """
    Record a behavioral detection (port scan / DoS / brute force).

    `attack_type` is the threat label (e.g. "Port scan"), `score` is the
    intensity that triggered it (port count, packet count, attempt count).
    A per-IP/per-type cooldown stops a sustained attack from flooding the
    log. Returns True if recorded, False if suppressed by the cooldown.
    """
    key = (ip, attack_type)
    now = time.time()
    if now - _last_behavior.get(key, 0) < ALERT_COOLDOWN:
        return False
    _last_behavior[key] = now

    log_threat(ip, "inbound", attack_type, severity, score, detail)
    if ENABLE_EMAIL:
        send_email_alert(ip, attack_type, severity, detail)
    return True


def send_email_alert(src_ip, threat_type, severity, description):
    """Send an SMTP email for a detection. Requires the SMTP settings above."""
    subject = f"Security Alert [{severity.upper()}]: {threat_type}"
    body = (
        f"Time: {datetime.now().isoformat()}\n"
        f"IP: {src_ip}\n"
        f"Severity: {severity}\n"
        f"Description: {description}"
    )
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_RECIPIENT

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, ALERT_RECIPIENT, msg.as_string())
        server.quit()
        print(f"[+] Alert email sent for IP: {src_ip}")
    except Exception as e:
        print(f"[ERROR] Failed to send alert email: {e}")
