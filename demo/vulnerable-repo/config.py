"""Application configuration — DO NOT COMMIT THIS FILE."""

import os
import subprocess
import pickle

# Hardcoded AWS credentials (should use env vars or secrets manager)
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Dangerous: shell=True with user input
def run_user_command(user_input):
    subprocess.call(user_input, shell=True)

# Dangerous: eval on untrusted data
def process_data(data):
    return eval(data)

# Dangerous: pickle deserialization
def load_cache(filepath):
    with open(filepath, 'rb') as f:
        return pickle.loads(f.read())

# Dangerous: os.system
def cleanup():
    os.system("rm -rf /tmp/*")

# SQL injection via f-string
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id={user_id}"
    return query

# Hardcoded database URL
DATABASE_URL = "postgres://admin:password123@production-db.us-east-1.rds.amazonaws.com:5432/maindb"
