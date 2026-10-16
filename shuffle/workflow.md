# Shuffle workflow: Wazuh alert enrichment

| # | Node | What it does |
|---|---|---|
| 1 | **Webhook** | Receives the alert JSON from the Wazuh `shuffle` integration (level 6 and above). |
| 2 | **HTTP – Wazuh indexer** | Counts alerts from the same `data.srcip` in the last 24 hours (`wazuh-alerts-*/_count`). |
| 3 | **HTTP – Security Onion** | Searches network events for the same attack pattern (for example `UNION`). Matching is done on the pattern, not the IP, because the IP seen by the sensor can differ from the one in the proxy log. |
| 4 | **Execute Python** | Decodes the URL and builds a short summary for the analyst. See [`enrich_and_format.py`](enrich_and_format.py). |
| 5 | **E-mail** | Sends the summary to the analyst. |

## Why enrich at all?

A raw Wazuh alert tells you *what* matched. The analyst also needs to know:

- **Is this a one-off or a campaign?** The 24-hour count from the same IP answers that quickly.
- **Do other sensors see it too?** The Security Onion lookup shows whether the attack is visible on the network.
- **Did it work?** The HTTP status in the summary, plus the reminder to read the request, keeps the analyst from trusting the severity level blindly.

## Problems I solved while building it

- **Variables not resolving in the Python node.** Shuffle inserts values like `$exec.field` as text, so quotes and nested JSON broke the script. I passed the whole alert as one value and parsed it in Python instead.
- **`json.loads` failing on Shuffle output.** Some values arrived as Python-style dictionaries (single quotes). `ast.literal_eval()` parsed them safely where `json.loads()` could not.
