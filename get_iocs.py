"""
Indicator-of-Compromise (IoC) updater.

Downloads the IPsum threat-intelligence feed (https://github.com/stamparm/ipsum)
and writes every IP whose score is high enough to Malicious_IP.csv.

IPsum aggregates 30+ public blocklists into a single file. Each IP carries a
score = the number of those lists that flagged it, so a higher score means
higher confidence. Filtering by a minimum score keeps the blocklist accurate
and avoids the false positives a raw "every-IP" feed produces.
"""

import csv
import re
import urllib.request

# Raw IPsum feed: lines of "<IP>\t<score>", with "#" comment lines.
IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
OUTPUT_FILE = "Malicious_IP.csv"

# Strict IPv4 matcher: each octet must be 0-255 (rejects junk like 999.1.1.1).
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4_RE = re.compile(rf"^(?:{_OCTET}\.){{3}}{_OCTET}$")


def update_from_IoCs(min_score=3, url=IPSUM_URL, output=OUTPUT_FILE):
    """
    Download the IPsum feed and save IPs with score >= `min_score` to
    `output` as a two-column CSV: ip,score.

    On any failure the existing Malicious_IP.csv is left untouched so the
    IDS can still run with the last good blocklist.
    """
    print(f"[*] Downloading IoC feed from {url} ...")
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "pyshark-ids"})
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[ERROR] Failed to download IoC feed: {e}")
        print("[*] Keeping the existing Malicious_IP.csv (if present).")
        return

    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, score = parts[0], parts[1]
        if not _IPV4_RE.match(ip) or not score.isdigit():
            continue
        if int(score) >= min_score:
            rows.append((ip, int(score)))

    if not rows:
        print("[WARNING] Feed parsed but produced 0 IPs; keeping existing Malicious_IP.csv.")
        return

    try:
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "score"])
            writer.writerows(rows)
    except Exception as e:
        print(f"[ERROR] Failed to write {output}: {e}")
        return

    print(f"[+] Saved {len(rows)} malicious IPs (score >= {min_score}) to {output}")


if __name__ == "__main__":
    # Allow running this module on its own to refresh the blocklist.
    update_from_IoCs()
