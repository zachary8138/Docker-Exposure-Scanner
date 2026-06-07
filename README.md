# Docker Exposure Scanner

Very fast, read only, checks for exposed Docker API (port **2375**) and Docker registry (port **5000**) endpoints. Optionally inspects an open Docker API for container metadata and scans container environment variables against common secret patterns. Be safe out there !

## Requirements

- Python **3.10+**
- No third-party packages required for TCP probing
- **`requests`** required only when using `--inspect` (install via optional extra below)

## Installation

```bash
cd docker-scanner
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[inspect]"
```

TCP-only (no HTTP inspect):

```bash
pip install -e .
```

## Usage

```bash
# Single host
docker-exposure-scan --targets 192.168.1.10

# CIDR range with deeper inspection when port 2375 is open
docker-exposure-scan --targets 10.0.0.0/24 --inspect --timeout 1.0

# CI-friendly: fail if any high-or-worse finding
docker-exposure-scan --targets 10.0.0.0/24 --fail-on high

# Append machine-readable output
docker-exposure-scan --targets 192.168.1.10 --jsonl findings.jsonl
```

Run without installing (from repo root):

```bash
PYTHONPATH=src python3 -m docker_scanner --targets 127.0.0.1
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--targets` | *(required)* | One or more IPs, hostnames, or CIDRs (e.g. `1.2.3.4`, `10.0.0.0/24`) |
| `--timeout` | `0.7` | Per-connection timeout in seconds |
| `--concurrency` | `256` | Maximum concurrent probes |
| `--inspect` | off | If port 2375 is open, query read-only Docker API endpoints and scan container env vars |
| `--jsonl` | � | Append findings as JSON Lines to this file |
| `--fail-on` | � | Exit code `2` if any finding at or above this severity (`low`, `medium`, `high`, `critical`) |

## What it checks

| Check | Severity | When |
|-------|----------|------|
| `docker_port_2375_open` | critical | TCP connect to port 2375 succeeds |
| `docker_registry_port_5000_open` | high | TCP connect to port 5000 succeeds |
| `docker_api_open` | critical | `--inspect`: unauthenticated `/version` responds |
| `docker_api_containers_listable` | high | `--inspect`: container list is readable |
| `docker_container_env_possible_secret` | critical | `--inspect`: env vars match secret patterns |
| `docker_dependency_missing` | medium | `--inspect` requested but `requests` not installed |

CIDR targets are expanded to individual host addresses before probing.

## Output

Each finding is printed to stdout:

```text
[CRITICAL] docker_port_2375_open tcp://10.0.0.5:2375 - Docker API port 2375 is open (often unauthenticated)
```

With `--jsonl`, the same finding is appended as one JSON object per line.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed; no finding met `--fail-on` threshold (or `--fail-on` not set) |
| `2` | At least one finding met or exceeded `--fail-on` severity |

## Project layout

```text
docker-scanner/
  pyproject.toml
  README.md
  src/docker_scanner/
    cli.py          # CLI entry point
    scanner.py      # Probe and inspect logic
    findings.py     # Finding model and output
    patterns.py     # Secret regex patterns (inspect mode)
```

## Authorization

Only scan networks and hosts you are **explicitly authorized** to test. Exposed Docker APIs are a serious security risk; this tool is intended for defensive auditing and remediation.

## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.
