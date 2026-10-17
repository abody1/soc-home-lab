#!/bin/bash
# Container entrypoint for the nginx-proxy container (Nginx + Wazuh agent + auth logger)
set -e

touch /var/log/nginx/access.log /var/log/nginx/error.log
mkdir -p /var/log/authlog && touch /var/log/authlog/auth-events.json
rsyslogd

python3 /opt/auth_logger.py &

/var/ossec/bin/wazuh-control start

exec nginx -g 'daemon off;'
