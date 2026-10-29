#!/usr/bin/env bash
set -e
cd /app
# install on first run or when package.json changed
if [ ! -d node_modules ] || [ package.json -nt node_modules ]; then
  npm install
fi
npm run dev
