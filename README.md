# BIG-IQ Inventory Export

Python CLI tool to export BIG-IQ inventory data (virtual servers, pools, pool members) via the F5 BIG-IQ REST API, with optional CSV output.

## Prerequisites

- Python 3.12+
- Access to a BIG-IQ instance with valid credentials

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 bigiq-inventory-export.py --username <user> --hostname <bigiq-host> [--password <password>] [--csv output.csv] [--debug]
```

### Arguments

| Argument       | Required | Description                          |
|----------------|----------|--------------------------------------|
| `--username`   | Yes      | BIG-IQ username                      |
| `--password`   | No       | Password (falls back to `BIGIQ_PASSWORD` env var, then secure prompt) |
| `--hostname`   | Yes      | BIG-IQ host (IP address or FQDN)     |
| `--csv`        | No       | Path to write CSV output             |
| `--debug`      | No       | Enable debug logging                 |

## Exported Data

When `--csv output.csv` is provided, three files are generated:

| File                       | Contents                          |
|----------------------------|-----------------------------------|
| `output.csv`               | LTM virtual server configurations |
| `output_pools.csv`         | LTM pool configurations           |
| `output_pool_members.csv`  | Pool member details               |

## Notes

This script is not maintained by F5, Inc. and no support/warranty is expressed or implied.
