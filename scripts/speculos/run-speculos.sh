#!/bin/bash
# Runs INSIDE the lima VM. Starts speculos backgrounded; log at ~/speculos.log (guest).
pkill -f 'venv/bin/speculos' 2>/dev/null; sleep 1
# The VM mounts .speculos-vm at the same path as on the host (see speculos.yaml).
ELF="$(cd "$(dirname "$0")" && pwd)/app/app.elf"
nohup ~/venv/bin/speculos --model nanosp --display headless --apdu-port 9999 --api-port 5000 "$ELF" > ~/speculos.log 2>&1 < /dev/null &
disown
echo started pid $!
