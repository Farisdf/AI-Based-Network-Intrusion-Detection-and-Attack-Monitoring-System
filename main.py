"""
Network IDS entry point.

Two modes:

  Live  (default)   python main.py
        Refreshes the IP blocklist, then sniffs the configured interface.

  Replay            python main.py <capture-file.pcap>
        Feeds a saved capture file through the IDS - used to test the
        port-scan / DoS / brute-force detectors. No download, no admin.

View detections in the web dashboard:  python dashboard.py
"""

import sys
import get_iocs as IoC
import IDS as ids


def main():
    print("[*] Network IDS starting up.")

    # ---- Configuration ----
    NIC = "Ethernet 4"    # VirtualBox Host-Only Adapter (Kali <-> Windows on 192.168.56.0/24)
    check_ioc = 1         # 1 = enable IP-blocklist checking
    min_score = 3         # blocklist: flag IPs listed by >= this many feeds
    refresh_iocs = True   # re-download the blocklist on startup (live mode)

    # A capture file given on the command line switches to replay mode.
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else None

    if pcap_file:
        # Replay mode - behavioral testing. Skip the download and just reuse
        # whatever Malicious_IP.csv is already present.
        print(f"[*] Replay mode - capture file: {pcap_file}")
        ids._read_file(pcap_file, check_ioc)
    else:
        if refresh_iocs:
            IoC.update_from_IoCs(min_score=min_score)
        print(f"[*] Live mode - sniffing on interface: {NIC}")
        print("[*] View detections in the dashboard:  python dashboard.py")
        ids._read_pcap(NIC, check_ioc)


if __name__ == "__main__":
    main()
