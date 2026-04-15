# SAP Log Forwarder & Wazuh Monitor

A unified daemon for forwarding SAP log files via UDP syslog and syncing SAP SCA results to a Wazuh manager.

## Features

- **Log Forwarding** — tails up to 4 static files + 1 date-rotating file, forwards new lines over UDP
- **Auto-decryption** — XOR/Base64 encrypted files are transparently decrypted before forwarding
- **File rotation detection** — inode tracking survives log rotates and truncates
- **Midnight auto-reset** — position trackers reset at 00:00 daily
- **SAP → Wazuh sync** — detects XML changes, filters noise, SCP-transfers to Wazuh manager
- **Config file support** — drive everything from `config.yaml` instead of CLI flags

## Quick Start

```bash
# 1. Install system dependencies
./install.sh

# 2. Configure (edit defaults as needed)
cp config.yaml my_config.yaml
vim my_config.yaml

# 3. Run
python3 log_forwarder_benchmark.py --config my_config.yaml

# Or interactive mode (no args)
python3 log_forwarder_benchmark.py
```

## CLI Usage

```bash
# Log forwarding only
python3 log_forwarder_benchmark.py --non-interactive --log-monitor -i 10.0.0.100 -p 514

# SAP-to-Wazuh only
python3 log_forwarder_benchmark.py --non-interactive --sap-wazuh --wazuh-host 192.168.1.100

# Both monitors
python3 log_forwarder_benchmark.py --non-interactive --log-monitor --sap-wazuh -i 10.0.0.100 --wazuh-host 192.168.1.100

# Reset a specific file's position tracker
python3 log_forwarder_benchmark.py --reset-file file2

# Reset all trackers
python3 log_forwarder_benchmark.py --reset
```

## Config File

All settings can be placed in `config.yaml` — see the bundled example. Pass it with `--config config.yaml`.

## Running as a Service

```bash
sudo cp log_forwarder.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now log_forwarder
sudo journalctl -fu log_forwarder
```

## Requirements

- Python 3.7+
- `netcat` (`nc`) — UDP log forwarding
- `openssh-client` (`scp`, `ssh`) — Wazuh transfer
- `expect` — password-based SSH automation
- `pyyaml` — config file support (`pip install pyyaml`)
