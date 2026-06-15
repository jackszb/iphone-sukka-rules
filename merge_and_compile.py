import json
import ssl
import subprocess
import urllib.request

# -----------------------------
# URL LISTS
# -----------------------------

DIRECT_URLS = [
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/apple_cn.json",
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/apple_cdn.json",
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/microsoft_cdn.json",
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/domestic.json",
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/direct.json",
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/lan.json",
]

PROXY_URLS = [
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/domainset/cdn.json",
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/domainset/download.json",
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/domainset/icloud_private_relay.json",
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/ai.json",
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/apple_intelligence.json",
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/apple_services.json",
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/microsoft.json",
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/cdn.json",
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/global.json",
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/my_proxy.json",
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/my_tw.json",
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/my_us.json",
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/stream.json",
  "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/telegram.json",
]

REJECT_URLS = [
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/domainset/reject.json",
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/domainset/reject_extra.json",
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/domainset/reject_phishing.json",
]

IP_URLS = [
    "https://raw.githubusercontent.com/jackszb/sukka/main/ip_custom_rules.json",
]


# -----------------------------
# Fetch & merge
# -----------------------------

def process_urls(urls, ssl_context):
    master_rules = {}

    for url in urls:
        url = url.strip()
        if not url:
            continue

        try:
            print(f"  Fetching: {url}")

            with urllib.request.urlopen(url, context=ssl_context) as response:
                data = json.loads(response.read().decode("utf-8"))

            if "rules" in data and isinstance(data["rules"], list):
                for rule in data["rules"]:
                    for key, value in rule.items():
                        master_rules.setdefault(key, [])

                        if isinstance(value, list):
                            master_rules[key].extend(value)
                        else:
                            master_rules[key].append(value)

        except Exception as e:
            print(f"  [ERROR] {url}: {e}")

    return master_rules


# -----------------------------
# Save JSON + compile SRS
# -----------------------------

def save_json_and_compile(master_rules, json_file, srs_file):
    """
    dedupe + sort + output json + compile srs
    """

    final_rule = {}

    # ✅ allowed rule keys (include domain_regex)
    allowed_keys = {
        "domain",
        "domain_suffix",
        "domain_keyword",
        "domain_regex",
        "ip_cidr",
        "ip"
    }

    for key, values in master_rules.items():
        unique_values = sorted(set(values))  # dedupe + sort

        if not unique_values:
            continue

        # only keep supported sing-box v4 fields
        if key in allowed_keys:
            final_rule[key] = unique_values

    data = {
        "version": 4,
        "rules": [final_rule]
    }

    # -----------------------------
    # 1. SAVE JSON
    # -----------------------------
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"  JSON saved: {json_file}")

    # -----------------------------
    # 2. COMPILE SRS
    # -----------------------------
    try:
        result = subprocess.run(
            ["sing-box", "rule-set", "compile", "--output", srs_file, json_file],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print(f"  SRS compiled: {srs_file}")
        else:
            print(f"  [SRS ERROR]: {result.stderr}")

    except FileNotFoundError:
        print("  [WARNING] sing-box not found, only JSON generated")


# -----------------------------
# MAIN
# -----------------------------

def main():
    ssl_context = ssl._create_unverified_context()

    print("\n=== DIRECT ===")
    direct = process_urls(DIRECT_URLS, ssl_context)
    save_json_and_compile(direct, "direct_rules.json", "direct_rules.srs")

    print("\n=== PROXY ===")
    proxy = process_urls(PROXY_URLS, ssl_context)
    save_json_and_compile(proxy, "proxy_rules.json", "proxy_rules.srs")

    print("\n=== REJECT ===")
    reject = process_urls(REJECT_URLS, ssl_context)
    save_json_and_compile(reject, "reject_rules.json", "reject_rules.srs")

    print("\n=== IP ===")
    ip = process_urls(IP_URLS, ssl_context)
    save_json_and_compile(ip, "ip_rules.json", "ip_rules.srs")

    print("\n=== ALL DONE ===")
if __name__ == "__main__":
    main()
