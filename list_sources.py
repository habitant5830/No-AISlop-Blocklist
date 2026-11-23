from urllib.request import urlopen

sources = [
    "https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/refs/heads/main/noai_hosts.txt"
]

all_lines = []
filtered_lines = []

for url in sources:
    with urlopen(url, timeout=15) as resp:
        text = resp.read().decode("utf-8")
        all_lines.extend(text.splitlines())  

    for raw_line in all_lines:
        line = raw_line.strip()

        # Filter out comments
        if not line or line.startswith("#"):
            continue
        else:
            # Check if rule is already in adblock format
            if line.startswith("||"):
                filtered_lines.append(f"{line}")
            else:
                parts = line.split()

                # Make adblock style rules
                if len(parts) >= 2:
                    filtered_lines.append(f"||{parts[1]}^")
                else:
                    filtered_lines.append(f"||{parts[0]}^")

# De-duplication
unique_rules = list(dict.fromkeys(filtered_lines))

with open("denylist.txt", "w", encoding="utf-8") as f:
    for rule in unique_rules:
        f.write(f"{rule}\n")
