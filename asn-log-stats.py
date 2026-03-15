#!/usr/bin/env python3
# =============================================================
# asn-log-stats.py
# Analizza /var/log/kern.log e conta i pacchetti droppati per ASN
# Uso:
#   python3 /usr/local/bin/asn-log-stats.py
#   python3 /usr/local/bin/asn-log-stats.py --top 20
#   python3 /usr/local/bin/asn-log-stats.py --since "2024-01-01"
# =============================================================

import sys
import re
import argparse
import maxminddb
from collections import defaultdict
from datetime import datetime

MMDB     = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
ASN_FILE = "/etc/asn-blocklist.txt"
LOG_FILE = "/var/log/kern.log"

def parse_args():
    p = argparse.ArgumentParser(description="Statistiche blocco ASN da log kernel")
    p.add_argument("--top",   type=int, default=30,  help="Mostra i top N ASN (default: 30)")
    p.add_argument("--since", type=str, default=None, help="Filtra log da data (es: 'Mar 15')")
    p.add_argument("--log",   type=str, default=LOG_FILE, help="File di log da analizzare")
    return p.parse_args()

def load_asn_descriptions():
    descs = {}
    try:
        with open(ASN_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('#', 1)
                asn = parts[0].strip().upper().lstrip('AS')
                desc = parts[1].strip() if len(parts) > 1 else ""
                descs[asn] = desc
    except FileNotFoundError:
        pass
    return descs

def load_mmdb():
    """Carica il mapping IP->ASN dal database MaxMind in memoria"""
    ip_to_asn = {}
    print("[*] Carico database MaxMind...", flush=True)
    with maxminddb.open_database(MMDB) as db:
        for network, record in db:
            if not record:
                continue
            if ':' in str(network):
                continue
            asn = str(record.get('autonomous_system_number', ''))
            org = record.get('autonomous_system_organization', '')
            if asn:
                ip_to_asn[str(network)] = (asn, org)
    print(f"[*] {len(ip_to_asn)} prefissi IPv4 caricati", flush=True)
    return ip_to_asn

def find_asn_for_ip(ip, ip_to_asn):
    """Trova l'ASN per un IP cercando il prefisso più specifico"""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        best = None
        best_prefix = -1
        for network_str, asn_info in ip_to_asn.items():
            try:
                net = ipaddress.ip_network(network_str)
                if ip_obj in net:
                    if net.prefixlen > best_prefix:
                        best_prefix = net.prefixlen
                        best = asn_info
            except Exception:
                continue
        return best
    except Exception:
        return None

def parse_log_fast(log_file, since=None):
    """Estrae gli IP sorgente dalle righe [ASN-BLOCK] del log"""
    ip_pattern = re.compile(r'\[ASN-BLOCK\].*?SRC=(\d+\.\d+\.\d+\.\d+)')
    ip_counts = defaultdict(int)
    total_lines = 0
    skipped = 0

    try:
        with open(log_file, 'r', errors='replace') as f:
            for line in f:
                if '[ASN-BLOCK]' not in line:
                    continue
                if since and since not in line:
                    skipped += 1
                    continue
                m = ip_pattern.search(line)
                if m:
                    ip_counts[m.group(1)] += 1
                    total_lines += 1
    except FileNotFoundError:
        print(f"ERRORE: file di log non trovato: {log_file}")
        print("Assicurati che il logging sia attivo:")
        print("  iptables -I INPUT 1 -m set --match-set blocked_asn src -j LOG --log-prefix \"[ASN-BLOCK] \" --log-level 4 --log-limit 10/min")
        sys.exit(1)

    return ip_counts, total_lines

def main():
    args = parse_args()

    print(f"\n{'='*65}")
    print(f"  Statistiche Blocco ASN — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*65}\n")

    # Carica descrizioni ASN
    descs = load_asn_descriptions()

    # Parsea il log
    print(f"[*] Analizzo {args.log}...", flush=True)
    ip_counts, total_events = parse_log_fast(args.log, args.since)

    if total_events == 0:
        print("\nNessun evento [ASN-BLOCK] trovato nel log.")
        print("Attiva il logging con:")
        print('  iptables -I INPUT 1 -m set --match-set blocked_asn src -j LOG --log-prefix "[ASN-BLOCK] " --log-level 4 --log-limit 10/min')
        sys.exit(0)

    print(f"[*] {total_events} eventi trovati da {len(ip_counts)} IP univoci", flush=True)

    # Raggruppa per ASN usando MaxMind
    # Approccio veloce: carica tutti i prefissi una volta sola
    asn_hits    = defaultdict(int)
    asn_ips     = defaultdict(set)
    asn_org     = {}
    unmatched   = 0

    import ipaddress

    print("[*] Associo IP agli ASN...", flush=True)
    with maxminddb.open_database(MMDB) as db:
        for ip, count in ip_counts.items():
            try:
                result = db.get(ip)
                if result:
                    asn = str(result.get('autonomous_system_number', ''))
                    org = result.get('autonomous_system_organization', '')
                    if asn:
                        asn_hits[asn] += count
                        asn_ips[asn].add(ip)
                        if asn not in asn_org:
                            asn_org[asn] = org
                    else:
                        unmatched += count
                else:
                    unmatched += count
            except Exception:
                unmatched += count

    # Stampa risultati
    sorted_asns = sorted(asn_hits.items(), key=lambda x: -x[1])
    top_asns    = sorted_asns[:args.top]
    total_hits  = sum(asn_hits.values())

    print(f"\n{'ASN':<12} {'Pacchetti':>10} {'%':>6} {'IP Univoci':>11}  Descrizione")
    print("-" * 75)

    for asn, hits in top_asns:
        pct   = hits / total_hits * 100
        uniq  = len(asn_ips[asn])
        # Usa descrizione dal file ASN se disponibile, altrimenti quella del mmdb
        desc  = descs.get(asn) or asn_org.get(asn, '')
        print(f"AS{asn:<10} {hits:>10} {pct:>5.1f}% {uniq:>11}  {desc}")

    print("-" * 75)
    print(f"{'TOTALE':<12} {total_hits:>10} {'100%':>6} {len(ip_counts):>11}  IP univoci")

    if unmatched:
        print(f"\n  Non classificati: {unmatched} pacchetti")

    if len(sorted_asns) > args.top:
        print(f"\n  (mostrati {args.top} su {len(sorted_asns)} ASN — usa --top N per vedere di più)")

    print()

if __name__ == "__main__":
    main()
