# BIG-IQ Inventory Export

Python CLI tool to export BIG-IQ inventory data (virtual servers, pools, pool members) via the F5 BIG-IQ REST API, with optional CSV output.

## Prerequisites

- Python 3.x
- Access to a BIG-IQ instance with valid credentials

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 bigiq-inventory-export.py --username <user> --hostname <bigiq-host> [options]
```

### Authentication

The password is read from the `BIGIQ_PASSWORD` environment variable. If not set, the script will prompt interactively.

```bash
export BIGIQ_PASSWORD='yourpassword'
python3 bigiq-inventory-export.py --username admin --hostname 10.0.0.1 --insecure
```

### Arguments

| Argument       | Required | Description                                            |
|----------------|----------|--------------------------------------------------------|
| `--username`   | Yes      | BIG-IQ username                                        |
| `--hostname`   | Yes      | BIG-IQ host (IP address or FQDN)                       |
| `--csv`        | No       | Path to write CSV output (prints to stdout if omitted) |
| `--ca-cert`    | No       | Path to CA bundle for TLS certificate verification     |
| `--insecure`   | No       | Disable TLS certificate verification                   |
| `--provider`   | No       | Authentication provider (default: `local`)             |
| `--debug`      | No       | Enable debug logging                                   |

### TLS Verification

By default, TLS certificate verification is enabled. For self-signed certificates:

- Use `--ca-cert /path/to/ca-bundle.pem` to provide a custom CA bundle
- Use `--insecure` to disable verification entirely (not recommended for production)

## Exported Data

When `--csv output.csv` is provided, three files are generated:

| File                       | Contents                          |
|----------------------------|-----------------------------------|
| `output.csv`               | LTM virtual server configurations |
| `output_pools.csv`         | LTM pool configurations           |
| `output_pool_members.csv`  | Pool member details               |

When `--csv` is omitted, all data is printed to stdout.

## Notes

This script is not maintained by F5, Inc. and no support/warranty is expressed or implied.
