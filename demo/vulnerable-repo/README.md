# Vulnerable Demo App

This is an intentionally vulnerable application used to demonstrate ButterFence's scanning capabilities.

**DO NOT use this code in production!** Every file contains security anti-patterns.

## Issues planted:
- Hardcoded API keys and credentials (.env, config.py, server.js)
- SSH private key committed to repo
- GCP service account credentials
- Dangerous Python patterns (eval, exec, pickle, subprocess shell=True)
- SQL injection via f-strings
- Command injection in Node.js
- Dangerous deployment scripts (curl|sh, force push, privileged Docker)
- Docker escape vectors (privileged, root mount, docker.sock)
- Cloud credential exposure
