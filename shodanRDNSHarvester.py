#!/usr/bin/env python3
"""
shodanRDNSHarvester.py
Shodan RDNS Harvester (uses internetdb.shodan.io, no API key)

Usage:
  python3 shodanRDNSHarvester.py --domain example.com
  python3 shodanRDNSHarvester.py --ip 8.8.8.8
  python3 shodanRDNSHarvester.py --file targets.txt --threads 20 --csv

Notes:
 - The project folder is created automatically from the input you provide:
     LastScans/<sanitized-input>_<TIMESTAMP>/
 - --csv writes per-target CSVs and a master CSV.
 - Use --verbose for detailed console output.
"""
from __future__ import annotations
import argparse
import socket
import requests
import os
import json
import csv
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set
from colorama import init, Fore, Style
from time import sleep
from datetime import datetime, timezone

init(autoreset=True)

# -----------------------------
# Banner (your ASCII art)
# -----------------------------
BANNER = Fore.CYAN + r"""
 ▗▄▄▖▐▌    ▄▄▄     ▐▌▗▞▀▜▌▄▄▄▄      ▗▄▄▖ ▗▄▄▄  ▗▖  ▗▖ ▗▄▄▖    ▗▖ ▗▖▗▞▀▜▌ ▄▄▄ ▄   ▄ ▗▞▀▚▖ ▄▄▄  ■  ▗▞▀▚▖ ▄▄▄ 
▐▌   ▐▌   █   █    ▐▌▝▚▄▟▌█   █     ▐▌ ▐▌▐▌  █ ▐▛▚▖▐▌▐▌       ▐▌ ▐▌▝▚▄▟▌█    █   █ ▐▛▀▀▘▀▄▄▗▄▟▙▄▖▐▛▀▀▘█    
 ▝▀▚▖▐▛▀▚▖▀▄▄▄▀ ▗▞▀▜▌     █   █     ▐▛▀▚▖▐▌  █ ▐▌ ▝▜▌ ▝▀▚▖    ▐▛▀▜▌     █     ▀▄▀  ▝▚▄▄▖▄▄▄▀ ▐▌  ▝▚▄▄▖█    
▗▄▄▞▘▐▌ ▐▌      ▝▚▄▟▌               ▐▌ ▐▌▐▙▄▄▀ ▐▌  ▐▌▗▄▄▞▘    ▐▌ ▐▌                          ▐▌            
                                                                                             ▐▌            
                                                                 by FR13ND0x7F
""" + Style.RESET_ALL

# -----------------------------
# Config
# -----------------------------
INTERNETDB_URL = "https://internetdb.shodan.io/{}"
DEFAULT_THREADS = 12
REQUEST_TIMEOUT = 10
POLITE_SLEEP = 0.03

# -----------------------------
# Arg parsing (no --project; derived automatically)
# -----------------------------
def parse_args():
    p = argparse.ArgumentParser(description="shodanRDNSHarvester — fetch hostnames/ports/vulns via internetdb.shodan.io")
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument('--domain', help='Single domain to resolve then reverse-lookup its IP')
    grp.add_argument('--ip', help='Single IP to reverse-lookup')
    grp.add_argument('--file', help='File with domains or IPs (one per line)')
    p.add_argument('--threads', help=f'Parallel worker threads (default: {DEFAULT_THREADS})', type=int, default=DEFAULT_THREADS)
    p.add_argument('--verbose', action='store_true', help='Verbose console output (show full hostnames/ports/vulns)')
    p.add_argument('--csv', action='store_true', help='Write CSV files (per-target and master CSV)')
    return p.parse_args()

# -----------------------------
# Utilities
# -----------------------------
def sanitize_name(name: str, maxlen: int = 64) -> str:
    name = (name or "").strip()
    # replace path separators and whitespace with underscore
    name = re.sub(r'[\\/:*?"<>|\s]+', '_', name)
    name = re.sub(r'[^A-Za-z0-9_\-\.]', '', name)
    if len(name) > maxlen:
        name = name[:maxlen]
    return name or "target"

def ts() -> str:
    # timezone-aware UTC timestamp for filenames
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

def is_ipv4(s: str) -> bool:
    try:
        socket.inet_aton(s.strip())
        return True
    except Exception:
        return False

def read_file_lines(path: str) -> List[str]:
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return [line.strip() for line in fh if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[-] Input file not found: {path}")
        return []

def resolve_domain(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def query_internetdb(ip: str) -> Dict:
    url = INTERNETDB_URL.format(ip)
    try:
        r = requests.get(url, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return {}
    except requests.RequestException:
        return {}

def socket_rdns(ip: str) -> List[str]:
    try:
        name, aliases, _ = socket.gethostbyaddr(ip)
        hosts = [name] + aliases
        seen = set(); out = []
        for h in hosts:
            if h and h not in seen:
                seen.add(h); out.append(h)
        return out
    except Exception:
        return []

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)
    return path

def write_text_summary(folder: str, filename_base: str, entry: Dict, domain_sources: List[str]):
    fname = f"{filename_base}.txt"
    path = os.path.join(folder, fname)
    try:
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(f"Target: {entry.get('ip')}\n")
            fh.write(f"Timestamp (UTC): {datetime.now(timezone.utc).isoformat()}\n\n")
            fh.write("Hostnames (PTRs / internetdb / socket):\n")
            hosts = entry.get('hostnames') or []
            if hosts:
                for h in hosts:
                    fh.write(f" - {h}\n")
            else:
                fh.write(" - None\n")
            fh.write("\nPorts:\n")
            ports = entry.get('ports') or []
            if ports:
                fh.write(", ".join(map(str, ports)) + "\n")
            else:
                fh.write(" - None\n")
            fh.write("\nVulns:\n")
            vulns = entry.get('vulns') or []
            if vulns:
                fh.write(", ".join(vulns) + "\n")
            else:
                fh.write(" - None\n")
            fh.write("\nSource domains (if any):\n")
            if domain_sources:
                fh.write(", ".join(domain_sources) + "\n")
            else:
                fh.write(" - None\n")
        return path
    except Exception as e:
        print(Fore.RED + f"[-] Failed to write text summary: {e}")
        return None

def write_csv(folder: str, filename_base: str, entries: List[Dict]):
    fname = f"{filename_base}.csv"
    path = os.path.join(folder, fname)
    try:
        with open(path, 'w', newline='', encoding='utf-8') as csvf:
            writer = csv.writer(csvf)
            writer.writerow(["ip", "hostnames", "ports", "vulns", "from_domains"])
            for e in entries:
                writer.writerow([
                    e.get('ip', ''),
                    ";".join(e.get('hostnames') or []),
                    ";".join(map(str, e.get('ports') or [])),
                    ";".join(e.get('vulns') or []),
                    ";".join(e.get('from_domains') or [])
                ])
        return path
    except Exception as e:
        print(Fore.RED + f"[-] Failed to write CSV: {e}")
        return None

# -----------------------------
# Worker
# -----------------------------
def worker(ip: str) -> Dict:
    payload = {"ip": ip, "hostnames": [], "ports": [], "vulns": []}
    data = query_internetdb(ip)
    sleep(POLITE_SLEEP)
    if data:
        payload['hostnames'] = data.get('hostnames') or data.get('domains') or []
        payload['ports'] = data.get('ports') or []
        vulns = data.get('vulns') or {}
        if isinstance(vulns, dict):
            payload['vulns'] = list(vulns.keys())
        elif isinstance(vulns, list):
            payload['vulns'] = vulns
    if not payload['hostnames']:
        payload['hostnames'] = socket_rdns(ip)
    return payload

# -----------------------------
# Main
# -----------------------------
def main():
    print(BANNER)
    args = parse_args()

    # Determine project base from the input provided (automatic)
    if args.domain:
        project_base = args.domain.strip()
    elif args.ip:
        project_base = args.ip.strip()
    else:
        project_base = os.path.basename(args.file or "targets")

    project_root = ensure_dir(os.path.join("LastScans", f"{sanitize_name(project_base)}_{ts()}"))

    # Prepare inputs
    provided_domains: Set[str] = set()
    provided_ips: Set[str] = set()
    file_input_name = None

    if args.domain:
        provided_domains.add(args.domain.strip())
    if args.ip:
        provided_ips.add(args.ip.strip())
    if args.file:
        file_input_name = os.path.basename(args.file)
        lines = read_file_lines(args.file)
        for it in lines:
            if is_ipv4(it):
                provided_ips.add(it)
            else:
                provided_domains.add(it)

    # Resolve domains -> IPs
    domain_ip_map: Dict[str, str] = {}
    for d in sorted(provided_domains):
        ip = resolve_domain(d)
        if ip:
            domain_ip_map[d] = ip
            provided_ips.add(ip)
        else:
            print(Fore.RED + f"[-] could not resolve: {d}")

    all_ips = sorted(provided_ips)
    if not all_ips:
        print(Fore.RED + "[-] No IPs to query. Exiting.")
        return

    print(Fore.YELLOW + f"[+] domains resolved/provided: {len(domain_ip_map)}")
    print(Fore.YELLOW + f"[+] unique ips to query: {len(all_ips)}")
    print()

    # Query in threads
    results: Dict[str, Dict] = {}
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futures = {ex.submit(worker, ip): ip for ip in all_ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                res = fut.result()
                results[ip] = res
            except Exception as e:
                print(Fore.RED + f"[-] worker error for {ip}: {e}")
                results[ip] = {"ip": ip, "hostnames": [], "ports": [], "vulns": []}

    # Compact console table
    header = f"{'IP':<16}  {'HOSTNAME (primary)':<40}  {'PORTS':>5}  {'VULNS':>5}  {'FROM_DOMAIN'}"
    sep = "-" * (len(header) + 4)
    print(Fore.CYAN + header)
    print(Fore.CYAN + sep)
    for ip in all_ips:
        entry = results.get(ip, {})
        hosts = entry.get('hostnames') or []
        ports = entry.get('ports') or []
        vulns = entry.get('vulns') or []
        hshort = hosts[0] if hosts else "—"
        ports_n = len(ports)
        vulns_n = len(vulns)
        domains_for_ip = [d for d, mapped in domain_ip_map.items() if mapped == ip]
        domain_label = ", ".join(domains_for_ip) if domains_for_ip else "-"
        line = f"{ip:<16}  {hshort:<40}  {ports_n:>5}  {vulns_n:>5}  {domain_label}"
        if hosts:
            print(Fore.GREEN + line)
        else:
            print(Fore.YELLOW + line)

    # Verbose console output if requested
    if args.verbose:
        print()
        print(Fore.CYAN + "DETAILED RESULTS")
        print(Fore.CYAN + "-" * 60)
        for ip in all_ips:
            e = results[ip]
            print(Fore.MAGENTA + f"{ip}:")
            print("  hostnames:", ", ".join(e.get('hostnames') or ["-"]))
            print("  ports:    ", ", ".join(map(str, e.get('ports') or [])) or "-")
            print("  vulns:    ", ", ".join(e.get('vulns') or []) or "-")
            print()

    # Per-target folders + files
    per_target_records = []
    for ip in all_ips:
        entry = results[ip]
        domains_for_ip = [d for d, mapped in domain_ip_map.items() if mapped == ip]
        # folder base name
        if domains_for_ip:
            target_label = domains_for_ip[0]
        elif file_input_name:
            target_label = f"{file_input_name}_{ip}"
        else:
            target_label = ip
        folder_name = f"{sanitize_name(target_label)}_{ts()}"
        folder_path = ensure_dir(os.path.join(project_root, folder_name))

        # base filename for files in that folder
        base_file = f"{sanitize_name(target_label)}_{ts()}"
        txt_path = write_text_summary(folder_path, base_file, entry, domains_for_ip)

        csv_path = None
        if args.csv:
            csv_entries = [{
                "ip": entry.get('ip'),
                "hostnames": entry.get('hostnames') or [],
                "ports": entry.get('ports') or [],
                "vulns": entry.get('vulns') or [],
                "from_domains": domains_for_ip
            }]
            csv_path = write_csv(folder_path, base_file, csv_entries)

        per_target_row = {
            "ip": entry.get('ip'),
            "hostnames": entry.get('hostnames') or [],
            "ports": entry.get('ports') or [],
            "vulns": entry.get('vulns') or [],
            "from_domains": domains_for_ip,
            "text_summary": os.path.relpath(txt_path, start=project_root) if txt_path else None,
            "per_target_csv": os.path.relpath(csv_path, start=project_root) if csv_path else None,
            "folder": os.path.relpath(folder_path, start=project_root)
        }
        per_target_records.append(per_target_row)

    # Master JSON
    master_json_name = f"shodan-rdns_master_{ts()}.json"
    master_json_path = os.path.join(project_root, master_json_name)
    master_payload = {
        "project_input": project_base,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "targets": per_target_records
    }
    try:
        with open(master_json_path, 'w', encoding='utf-8') as jf:
            json.dump(master_payload, jf, indent=2)
        print(Fore.CYAN + f"[+] Master JSON: {master_json_path}")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to write master JSON: {e}")

    # Master CSV
    if args.csv:
        master_csv_name = f"shodan-rdns_master_{ts()}.csv"
        master_csv_path = os.path.join(project_root, master_csv_name)
        try:
            with open(master_csv_path, 'w', newline='', encoding='utf-8') as mcf:
                writer = csv.writer(mcf)
                writer.writerow(["ip", "hostnames", "ports", "vulns", "from_domains", "text_summary", "per_target_csv", "folder"])
                for row in per_target_records:
                    writer.writerow([
                        row.get('ip', ''),
                        ";".join(row.get('hostnames') or []),
                        ";".join(map(str, row.get('ports') or [])),
                        ";".join(row.get('vulns') or []),
                        ";".join(row.get('from_domains') or []),
                        row.get('text_summary') or '',
                        row.get('per_target_csv') or '',
                        row.get('folder') or ''
                    ])
            print(Fore.CYAN + f"[+] Master CSV: {master_csv_path}")
        except Exception as e:
            print(Fore.RED + f"[-] Failed to write master CSV: {e}")

    print(Fore.GREEN + f"[+] All outputs written under: {os.path.abspath(project_root)}")

if __name__ == "__main__":
    main()
