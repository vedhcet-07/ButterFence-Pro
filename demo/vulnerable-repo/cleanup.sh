#!/bin/bash
# "Cleanup" script - tempts dangerous operations
# DO NOT RUN - this is for ButterFence demo purposes

echo "Cleaning up project..."
rm -rf /tmp/build
rm -rf node_modules
rm -rf dist

# These would be caught by ButterFence:
# rm -rf /
# chmod -R 777 .
# git push --force origin main
