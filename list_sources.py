from urllib.request import urlopen

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
    "https://raw.githubusercontent.com/alvi-se/ai-ublock-blacklist/refs/heads/master/list.txt"
]

pending_header = None
current_header = None
last_source = None
all_lines = []
debug_lines = []
final_lines= []
sorted_final_lines = []
seen_rules = set()
grouped = {}

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

    # Comparing headers
    if source_url != last_source:
        debug_lines.append(f"# === {source_url} ===")
        last_source = source_url
    debug_lines.append(f"||{host}^")

# De-duplication
for entry in debug_lines:
    if entry.startswith("# === "):
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
    if line.startswith("# === "):
        current_header = line
        grouped.setdefault(current_header, [])
    else:
        grouped[current_header].append(line)

for header, rules in grouped.items():
    rules.sort()
    if sorted_final_lines:
        sorted_final_lines.append("")
    sorted_final_lines.append(header)
    sorted_final_lines.extend(rules)

print("Fetched rules:", len(all_lines))
print("Unique Rules:", len(seen_rules))

if len(seen_rules) <= 0:
    print("0 rules generated.")
else:
    with open("blocklist.txt", "w", encoding="utf-8") as f:
        for rule in sorted_final_lines:
            f.write(f"{rule}\n")
