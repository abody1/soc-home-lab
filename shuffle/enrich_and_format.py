"""
Enrichment and formatting step for the Wazuh -> Shuffle workflow.

In the lab these steps run as separate nodes in Shuffle (webhook -> HTTP -> Python -> e-mail).
This file is a cleaned-up, standalone version of the same logic so it can be read and tested
outside Shuffle.

Input : one Wazuh alert in JSON (as sent by the Wazuh "shuffle" integration)
Output: a short, analyst-friendly text summary
"""

import json
import sys
from urllib.parse import unquote_plus

import requests

# --- Settings (replace with your own lab values) ---------------------------
INDEXER_URL = "https://WAZUH_INDEXER:9200"
INDEXER_AUTH = ("admin", "CHANGE_ME")
VERIFY_TLS = False  # lab only: self-signed certificate


def count_alerts_from_ip(src_ip: str, hours: int = 24) -> int:
    """Ask the Wazuh indexer how many alerts the same source IP produced recently."""
    query = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"data.srcip": src_ip}},
                    {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
                ]
            }
        }
    }
    r = requests.post(
        f"{INDEXER_URL}/wazuh-alerts-*/_count",
        json=query,
        auth=INDEXER_AUTH,
        verify=VERIFY_TLS,
        timeout=10,
    )
    r.raise_for_status()
    return r.json().get("count", 0)


def format_summary(alert: dict, wazuh_count: int, so_count: int, so_pattern: str = "UNION") -> str:
    """Build the e-mail text the analyst receives."""
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    url = unquote_plus(data.get("url", "-"))

    lines = [
        f"Alert:   {rule.get('description', '-')}",
        f"Rule:    {rule.get('id', '-')} (level {rule.get('level', '-')})",
        f"Agent:   {alert.get('agent', {}).get('name', '-')}",
        f"Source:  {data.get('srcip', '-')}",
        f"URL:     {url}",
        f"HTTP:    {data.get('id', '-')}",
        "",
        f"Wazuh enrichment:          {wazuh_count} alerts from the same IP in the last 24 hours.",
        f"Security Onion enrichment: {so_count} network events with the {so_pattern} pattern",
        "                           (matching is done on the attack pattern, not on the IP address).",
        "",
        "Note: the Wazuh level does not tell you whether the attack succeeded. Review the request itself.",
    ]

    # Improvement added after the findings (not in the first version of the workflow):
    # highlight the "severity paradox" – attack pattern + HTTP 200 = possible success
    if str(data.get("id")) == "200" and "union" in url.lower() and "select" in url.lower():
        lines.insert(0, "!! POSSIBLE SUCCESSFUL SQL INJECTION – HTTP 200 on a UNION SELECT request !!\n")

    return "\n".join(lines)


if __name__ == "__main__":
    # Offline test: python enrich_and_format.py ../samples/wazuh-alert-31106.json
    with open(sys.argv[1], encoding="utf-8") as f:
        sample_alert = json.load(f)
    print(format_summary(sample_alert, wazuh_count=12, so_count=0))
