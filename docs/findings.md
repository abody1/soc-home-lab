# Findings and lessons learned

## 1. Severity paradox

During testing, failed SQL injection attempts (HTTP 500) triggered **rule 31103 at level 7**, while the one request that actually returned the database schema (HTTP 200) triggered **rule 31106 at level 6**.

**Why it matters:** analysts often sort or filter by severity. Here the real compromise would be reviewed *after* the noise.

**What I did about it:**
- The Shuffle summary always shows the HTTP status and ends with a reminder that the level does not show success.
- I wrote a [proposed custom rule](../wazuh/local_rules.xml) that raises a level 12 alert when 31106 fires on a `UNION SELECT` request.

## 2. POST body blind spot

Wazuh's web rules analyse the access log line. The log contains the URL and status code but **not the request body**. SQL injection in a POST body, such as a login form, therefore produces no SQL injection alert.

### Recommended fix: an application-side authentication event

My first idea was to log more of each request. A reader on LinkedIn pointed out why that is the wrong direction: **logging full request bodies would put passwords and tokens into the logs**, which creates a new security and GDPR problem, adds a lot of noise and is hard to analyse.

The better fix is to let the **application** emit one small, structured event for every login attempt, with only what the analyst needs:

| Field | Why |
|---|---|
| `decision` | `success` or `failure` – the outcome the proxy log cannot see |
| `account` | which account was targeted |
| `correlation_id` | the same ID is added to the proxy log, so the event can be joined with the Nginx line and network data |
| `src_ip`, `timestamp` | for grouping and timelines |
| **never** | passwords, tokens, session cookies or other secrets |

Example of the proposed event (design, not yet implemented in the lab):

```json
{
  "event": "auth.login",
  "decision": "failure",
  "account": "admin@juice-sh.op",
  "src_ip": "203.0.113.50",
  "correlation_id": "7f3c2a9e-1b4d-4c55-9a0e-2f6d8b1e0c11",
  "timestamp": "2026-10-13T22:09:33Z"
}
```

With this event Wazuh can alert on patterns such as many failures for one account, failures from one IP across many accounts, or a success right after a burst of failures – without a single secret in the logs.

**The last step matters:** test end to end that the event really reaches the analyst's view in Wazuh, instead of assuming it does.

**Other ways to narrow the gap:**
- a WAF or ModSecurity in front of the application, sending its alerts (not full bodies) to Wazuh
- network inspection with Suricata/Zeek, when the traffic is visible and not encrypted

## 3. Host and network data complement each other

Security Onion reported **0 network events** for the same attack pattern that Wazuh detected every time. In a containerised lab, much of the traffic never crosses the interface the sensor listens on. In a real network, TLS has a similar effect. A SOC needs both host logs and network data, and needs to know where each one is blind.

## 4. Enrichment saves triage time

Seeing "12 alerts from the same IP in the last 24 hours" next to the alert immediately turns a single event into a pattern. That is the decision an analyst would otherwise make by searching manually.

## What I would add next

- Test and tune the proposed rule with `wazuh-logtest`
- Add a case in a case-management tool (for example TheHive or Security Onion cases) instead of only e-mail
- Automatic IP reputation lookup (for example AbuseIPDB) for external sources
- Implement the authentication event with a correlation ID, and add the same ID to the Nginx log format
- Write a Wazuh decoder and rules for the event, and verify end to end that it reaches the dashboard
