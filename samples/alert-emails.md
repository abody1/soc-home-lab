# Alert e-mails from the lab

Real summaries sent by the Shuffle workflow on 13 October 2026, translated from Swedish.
The attacker's IP address has been replaced with `203.0.113.50` (a documentation address). Everything else is unchanged.

## Path traversal – returned HTTP 200

```text
Alert:   A web attack returned code 200 (success).
Rule:    31106 (level 6)
Agent:   nginx-proxy
Source:  203.0.113.50
URL:     /rest/products/search?q=../../../../etc/passwd
HTTP:    200

Wazuh enrichment:          3 alerts from the same IP in the last 24 hours.
Security Onion enrichment: 0 network events with the UNION pattern.
```

## SQL injection attempts – failed (HTTP 500)

```text
Alert:   SQL injection attempt.
Rule:    31103 (level 7)
Agent:   nginx-proxy
Source:  203.0.113.50
URL:     /rest/products/search?q=apple'+UNION+SELECT+1--
HTTP:    500

Wazuh enrichment:          7 alerts from the same IP in the last 24 hours.
```

```text
URL:     /rest/products/search?q=apple'+UNION+SELECT+*+FROM+users--
HTTP:    500
Rule:    31103 (level 7)
Wazuh enrichment:          11 alerts from the same IP in the last 24 hours.
```

## SQL injection – succeeded (HTTP 200)

```text
Alert:   A web attack returned code 200 (success).
Rule:    31106 (level 6)
Agent:   nginx-proxy
Source:  203.0.113.50
URL:     /rest/products/search?q=qwert'))+UNION+SELECT+name,type,'3','4','5','6','7','8','9'+FROM+sqlite_master--
HTTP:    200

Wazuh enrichment:          12 alerts from the same IP in the last 24 hours.
Security Onion enrichment: 0 network events with the UNION pattern.
```

The alert count from the same IP grows from 3 to 12 within about seven minutes. That pattern is itself a useful signal: one source trying many variations is typical of manual or automated injection testing.
