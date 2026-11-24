from datetime import datetime, timezone
from urllib.request import urlopen
import socket
import time
import json

now = datetime.now(timezone.utc)

allowed_hosts = set()
try:
    with open("whitelist.txt", "r", encoding="utf-8") as f:
        for line in f:
            clean = line.split("#")[0].split("!")[0].strip().lower()
            if clean:
                clean = clean.removeprefix("www.").strip(".")
                allowed_hosts.add(clean)
except FileNotFoundError:
    print("File not found")

sources = [
    "manual_denylist.txt",
    "https://raw.githubusercontent.com/Stevoisiak/Stevos-AI-Blocklist/refs/heads/main/GenAI-Blocklist-URLs.txt",
    "https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/refs/heads/main/noai_hosts.txt"
]

pending_header = None
current_header = None
last_source = None
all_lines = []
debug_lines = []
final_lines= []
sorted_final_lines = []
seen_remote_hosts = set()
seen_rules = set()
known_dead = set()
grouped = {}
dns_cache = {}
kept_rules = 0

# Collecting dead domains
try:
    with open("debug/dead_strikes.json", "r", encoding="utf-8") as f:
        strikes = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    strikes = {}

def is_dead_domain(host, retries=2, delay=0.2, timeout=3.0):
        socket.setdefaulttimeout(timeout)
        for attempt in range(retries):
            try:
                socket.getaddrinfo(host, None)
                return False
            except (socket.gaierror, OSError):
                if attempt < retries - 1:
                    time.sleep(delay)
        return True

for url in sources:
    if url.startswith(("http://", "https://")):
        try:
            with urlopen(url, timeout=15) as resp:
                text = resp.read().decode("utf-8")
                for line in text.splitlines():
                    all_lines.append((url, line))
        except:
            print("Network connection failed to ",url)
    else:      
        try:
            with open(url, "r", encoding="utf-8") as f:
                for line in f:
                    all_lines.append((url, line))
        except FileNotFoundError:
            print("File not found")  

for source_url, raw_line in all_lines:

    # Filtering and Normalization    
    line = raw_line.strip()
    line = line.split("#")[0].strip()
    if not line or line.startswith("#"):
        continue
    parts = line.split()
    host = parts[-1].lower()
    host = host.removeprefix("||")
    host = host.removeprefix("https://")
    host = host.removeprefix("http://")
    host = host.removeprefix("www.")
    host = host.split("/")[0]
    host = host.split("$")[0]
    host = host.split(":")[0]
    host = host.split("^")[0]
    host = host.strip(".[]()\"'")
    if host == "":
        continue
    if host.replace(".", "").isdigit():
        continue

    # Disabled tld filtering
    '''tld = host.split(".")[-1]
    if tld == "ai":
        continue'''
      
    if len(host.split(".")) < 2:
        continue

    if host in allowed_hosts:
        continue

    if source_url.startswith(("http://", "https://")):
        seen_remote_hosts.add(host)
        if host not in dns_cache:
            dns_cache[host] = is_dead_domain(host)

        if dns_cache[host]:
            strikes[host] = strikes.get(host, 0) + 1
        else:
            strikes.pop(host, None)

        if strikes.get(host, 0) >= 10:
            continue

    # Comparing headers
    if source_url != last_source:
        debug_lines.append(f"! === {source_url} ===")
        last_source = source_url
    kept_rules = kept_rules + 1
    debug_lines.append(f"||{host}^")

# De-duplication
for entry in debug_lines:
    if entry.startswith("! === "):
        pending_header = entry
    else:
        if entry not in seen_rules:
            seen_rules.add(entry)
            if pending_header is not None:
                final_lines.append(pending_header)
                pending_header = None
            final_lines.append(entry)

# Sorting
for line in final_lines:
    if line.startswith("! === "):
        current_header = line
        grouped.setdefault(current_header, [])
    else:
        grouped[current_header].append(line)

for header, rules in grouped.items():
    rules.sort()
    if sorted_final_lines:
        sorted_final_lines.append("!")
    sorted_final_lines.append(header)
    sorted_final_lines.extend(rules)

# Curating header lines
last_modified = now.strftime("%d %b %Y %H:%M UTC")
version = now.strftime("%Y.%m%d.%H%M.%S")

header_lines = [
    "[Adblock Plus]",
    "! Title: No-AISlop-Blocklist",
    "! Description: Curated AI domain blocklist merged from remote sources and manual denylist.",
    "! Expires: 6 hours",
    f"! Last modified: {last_modified}",
    f"! Version: {version}",
    "! Syntax: AdBlock",
    f"! Number of entries: {len(seen_rules)}",
    "!",
]

# Collecting dead domains
try:
    with open("debug/dead_domains.txt", "r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip()
            if domain:
                known_dead.add(domain)
except FileNotFoundError:
    pass

stale_hosts = [host for host in strikes if host not in seen_remote_hosts]
for host in stale_hosts:
    del strikes[host]

newly_confirmed = [host for host, count in strikes.items() if count >= 10 and host not in known_dead]
if newly_confirmed:
    with open("debug/dead_domains.txt", "a", encoding="utf-8") as f:
        for domain in newly_confirmed:
            f.write(f"{domain}\n")
            known_dead.add(domain)

# Print outputs to the terminal
print("Fetched rules:", kept_rules)
print("Unique Rules:", len(seen_rules))
print("Dead domains:", len(known_dead))

# Write strikes into json
with open("debug/dead_strikes.json", "w", encoding="utf-8") as f:
    json.dump(strikes, f, indent=2, sort_keys=True)

# Write rules into blocklist
if len(seen_rules) <= 0:
    print("0 rules generated.")
else:
    with open("blocklist.txt", "w", encoding="utf-8") as f:
        for line in header_lines:
            f.write(f"{line}\n")
        for rule in sorted_final_lines:
            f.write(f"{rule}\n")
