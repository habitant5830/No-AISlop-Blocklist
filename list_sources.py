from urllib.request import urlopen

allowed_hosts = set()
try:
    with open("allowlist.txt", "r", encoding="utf-8") as f:
        for line in f:
            clean = line.split("#")[0].split("!")[0].strip().lower()
            if clean:
                clean = clean.removeprefix("www.").strip(".")
                allowed_hosts.add(clean)
except FileNotFoundError:
    print("File not found")

sources = [
    "https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/refs/heads/main/noai_hosts.txt",
    "https://raw.githubusercontent.com/habitant5830/No-AISlop-Blocklist/refs/heads/main/custom/denylist.txt",
    "https://raw.githubusercontent.com/Jadde-1/PiHole-list/main/AI-SLOP-SITES.txt",
    "https://raw.githubusercontent.com/Stevoisiak/Stevos-AI-Blocklist/refs/heads/main/GenAI-Blocklist-URLs.txt"
]

all_lines = []
filtered_lines = []

for url in sources:
    try:
        with urlopen(url, timeout=15) as resp:
            text = resp.read().decode("utf-8")
            all_lines.extend(text.splitlines())
    except:
        print("Network connection failed to ",url)

for raw_line in all_lines:
    line = raw_line.strip()
   
    # Filters
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
    host = host.strip(".")
    if host == "":
        continue
    if host.replace(".", "").isdigit():
        continue

    '''tld = host.split(".")[-1]
    if tld == "ai":
        continue'''
      
    if len(host.split(".")) < 2:
        continue

    if host in allowed_hosts:
        continue
    # Make adblock style rules
    filtered_lines.append(f"||{host}^")
      
# De-duplication
unique_rules = list(dict.fromkeys(filtered_lines))
unique_rules.sort()

if len(unique_rules) <= 0:
    print("0 rules generated.")
else:
    with open("denylist.txt", "w", encoding="utf-8") as f:
        for rule in unique_rules:
            f.write(f"{rule}\n")

