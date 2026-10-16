# Findings and lessons learned

## 1. Severity paradox

During testing, failed SQL injection attempts (HTTP 500) triggered **rule 31103 at level 7**, while the one request that actually returned the database schema (HTTP 200) triggered **rule 31106 at level 6**.

**Why it matters:** analysts often sort or filter by severity. Here the real compromise would be reviewed *after* the noise.

**What I did about it:**
- The Shuffle summary always shows the HTTP status and ends with a reminder that the level does not show success.
- I wrote a [proposed custom rule](../wazuh/local_rules.xml) that raises a level 12 alert when 31106 fires on a `UNION SELECT` request.

## 2. POST body blind spot

Wazuh's web rules analyse the access log line. The log contains the URL and status code but **not the request body**. SQL injection in a POST body, such as a login form, therefore produces no SQL injection alert.

**Options to close the gap:**
- a WAF or ModSecurity in front of the application, with its own audit log sent to Wazuh
- application logging of failed or suspicious queries
- network inspection with Suricata/Zeek (when the traffic is visible and not encrypted)

## 3. Host and network data complement each other

Security Onion reported **0 network events** for the same attack pattern that Wazuh detected every time. In a containerised lab, much of the traffic never crosses the interface the sensor listens on. In a real network, TLS has a similar effect. A SOC needs both host logs and network data, and needs to know where each one is blind.

## 4. Enrichment saves triage time

Seeing "12 alerts from the same IP in the last 24 hours" next to the alert immediately turns a single event into a pattern. That is the decision an analyst would otherwise make by searching manually.

## What I would add next

- Test and tune the proposed rule with `wazuh-logtest`
- Add a case in a case-management tool (for example TheHive or Security Onion cases) instead of only e-mail
- Automatic IP reputation lookup (for example AbuseIPDB) for external sources
- A ModSecurity WAF in front of Juice Shop to cover POST bodies
