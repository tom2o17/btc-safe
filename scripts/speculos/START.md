# Speculos (app-bitcoin-new testnet, nanosp) in a Lima VM

Dir: `.speculos-vm/` at the repo root, gitignored (lima 2.2.1 binaries in ./lima, VM config ./speculos.yaml). Set the mount path in speculos.yaml to its absolute path.
VM: lima instance `speculos` (vz, Ubuntu 24.04 arm64), state in ~/.lima/speculos. This dir is mounted at the same path in the guest.
Host ports: 127.0.0.1:9999 (APDU TCP), 127.0.0.1:5000 (REST API).

## Start
    cd .speculos-vm
    ./lima/bin/limactl start speculos            # first time ever: ./lima/bin/limactl start --name=speculos --tty=false ./speculos.yaml
    ./lima/bin/limactl shell speculos bash $PWD/run-speculos.sh   # (re)starts speculos, nohup'd; guest log ~/speculos.log

## Stop
    ./lima/bin/limactl shell speculos pkill -f venv/bin/speculos
    ./lima/bin/limactl stop speculos

## Fresh VM provisioning (only if the instance is deleted)
    ./lima/bin/limactl shell speculos bash -c 'sudo apt-get update && sudo apt-get install -y qemu-user-static python3-venv python3-dev gcc && python3 -m venv ~/venv && ~/venv/bin/pip install speculos'

## App
app/app.elf = CI artifact `bitcoin-testnet-app-nanosp` (id 10341056899) from LedgerHQ/app-bitcoin-new
branch master @ da3c8c9d1cab91a7614efe6cadf197c5cc7c3b50 (2026-09-14). App "Bitcoin Test" v2.5.1, SDK v26.6.2, NBGL.
No GitHub release ships ELFs; artifacts expire (~90 days) -- keep this copy.

## Seed
Speculos default (no --seed): "glory promote mansion idle axis finger extra february uncover one trip resource
lawn turtle enact monster seven myth punch hobby comfort wild raise skin". Master fingerprint f5acc2fd (verified via APDU e105000000).
To change: add `--seed "<mnemonic>"` in run-speculos.sh.

## Verify
    curl -s 127.0.0.1:5000/events?currentscreenonly=true
    curl -s -X POST -H 'Content-Type: application/json' -d '{"data":"e105000000"}' 127.0.0.1:5000/apdu   # -> f5acc2fd9000

## Buttons
    curl -X POST -H 'Content-Type: application/json' -d '{"action":"press-and-release"}' 127.0.0.1:5000/button/right   # left|right|both
Or POST /automation with a rules JSON for unattended approval.
Raw APDU TCP framing on 9999: 4-byte BE length + APDU; response 4-byte BE length + data + 2-byte SW.

## In the repo
These three files are copies kept in `scripts/speculos/`. The runtime dir `.speculos-vm/` (lima
binaries, the app ELF, logs) and `.venv-speculos/` are gitignored. To rebuild from scratch:
download Lima (Darwin arm64 tarball from github.com/lima-vm/lima/releases) into
`.speculos-vm/lima/`, copy these files into `.speculos-vm/`, fetch the ELF (below), then
`./lima/bin/limactl start --name=speculos --tty=false ./speculos.yaml` and provision.

ELF sha256 (app 2.5.1, nanosp, testnet): defeaf9cd949d8425454cd1c567219620a6e8742ed6f93ae510e9cadde874dbb
Speculos can't run natively on macOS: its launcher is a Linux ARM ELF run under
`qemu-arm-static` (Linux user-mode qemu). Hence the VM.
