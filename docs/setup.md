# Lab setup

Tested on Windows 11 with WSL2 and Docker Desktop.

## 1. Wazuh (single-node)

Wazuh runs from the official Docker deployment:

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.x
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Dashboard: `https://localhost` (default credentials from the Wazuh docs – change them).

## 2. Target application

```bash
cd lab
mkdir -p nginx-logs
docker compose up -d
```

Juice Shop is now reachable through the proxy at `http://localhost:8080`.

## 3. Wazuh agent on the proxy

1. Install a Wazuh agent and register it with the manager under the name `nginx-proxy`.
2. Add the `<localfile>` block from [`lab/wazuh-agent-localfile.xml`](../lab/wazuh-agent-localfile.xml) to the agent's `ossec.conf`.
3. Restart the agent.

## 4. Send alerts to Shuffle

1. Create a workflow in Shuffle that starts with a **Webhook** trigger and copy its URL.
2. Add the block from [`wazuh/integration-shuffle.xml`](../wazuh/integration-shuffle.xml) to the manager's `ossec.conf`, with your webhook URL.
3. Restart the manager.
4. Build the rest of the workflow as described in [`shuffle/workflow.md`](../shuffle/workflow.md).

## 5. Generate test traffic

Only against your own lab:

```text
http://localhost:8080/rest/products/search?q=apple'))+UNION+SELECT+1--
http://localhost:8080/rest/products/search?q=../../../../etc/passwd
```

Check the alerts in the Wazuh dashboard (rules 31103 and 31106) and the e-mail from Shuffle.
