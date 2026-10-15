# Software Inventory Extension

A Dynatrace Extensions 2.0 (Python, OneAgent-hosted) extension that collects the list of installed software from your hosts and reports it as metrics, so you can answer "what is installed where, and which version?" with DQL and dashboards.

**Current version:** 0.0.26

<!-- TODO: add a screenshot of the Software Inventory dashboard here -->
![Software Inventory dashboard](docs/images/software-inventory-dashboard.png)

## Overview

| Platform | Source | Status |
|---|---|---|
| Windows | Registry `Uninstall` keys (64-bit and 32-bit) | Supported |
| Linux (Ubuntu, Debian) | `dpkg-query` | Supported |
| Linux (RHEL, CentOS, Fedora) | `rpm -qa` | Supported |
| macOS (Homebrew) | `brew info` | Code present, not enabled (extension only loads on Windows/Linux) |

Each collection cycle reports:

- `software_inventory.programs.count` – number of installed programs per host.
- `software_inventory.programs.info` – one data point (value `1`) per installed program, with the dimensions `host.name`, `program_name`, `program_version`, `program_publisher`, `install_location` and `install_date`.

> The extension reports `programs.count` / `programs.info`; Dynatrace stores them with the `software_inventory.` prefix, so use the prefixed name in DQL.

## What's included

| Item | File |
|---|---|
| Extension definition | [extension/extension.yaml](extension/extension.yaml) |
| Extension code | [software_inventory/extension.py](software_inventory/extension.py) |
| Fleet Overview dashboard (all hosts) | [Software_Inventory_Fleet_Overview.json](Software_Inventory_Fleet_Overview.json) |
| Host Detail dashboard (single host) | [Software_Inventory_Host_Detail.json](Software_Inventory_Host_Detail.json) |
| Earlier dashboards (v0.1, legacy metric names) | [Software_Inventory_Dashboard v0.1.json](Software_Inventory_Dashboard%20v0.1.json), [Host_Profile_Dashboard v0.1.json](Host_Profile_Dashboard%20v0.1.json) |

### Dashboards

**Fleet Overview** – hosts reporting, installed programs, unique products, recent installs, software by publisher (donut), most widely installed software and programs per host (bar charts), software with more than one version, recent installations and the full inventory. Filter by hostname (multi-select).

<!-- TODO: screenshot -->

**Host Detail** – a single host: summary tiles, software by publisher, most recent installations and the complete software list with install locations.

<!-- TODO: screenshot -->

Both dashboards show the latest snapshot within the selected timeframe, so use a timeframe longer than your collection interval (the 2 hour default works for 30 minute collection).

## Requirements

- Dynatrace SaaS with OneAgent (Dynatrace version 1.285 or later) on the target hosts
- Python 3.10 or later on the machine used to build the extension. The extension is built for the **Python 3.14** OneAgent runtime (Python 3.10 reaches end of support on 26 October 2026; see the [runtime update notice](https://docs.dynatrace.com/docs/ingest-from/extensions/end-of-support/python-extension-runtime-update))
- `dt-extensions-sdk` >= 1.8.0 and `distro` >= 1.9.0 (installed via `pip install .`)
- Windows hosts: access to the `HKLM\SOFTWARE\...\Uninstall` registry keys
- Linux hosts: `dpkg-query` (Debian/Ubuntu) or `rpm` (RHEL/CentOS/Fedora) available to the OneAgent user

## How to set it up yourself

### 1. Clone and install the tooling

```
git clone <this repository>
cd software-inventory
python -m venv .venv
.venv\Scripts\activate        # Linux: source .venv/bin/activate
pip install ".[dev]"
```

### 2. Build and sign the extension

Extensions must be signed with your own developer certificate. Create a CA and developer certificate following [Sign extensions manually with OpenSSL](https://docs.dynatrace.com/docs/ingest-from/extensions/develop-your-extensions/sign-extensions/manually-openssl), then upload the CA certificate to your Dynatrace tenant's credential vault / OneAgent trust store as described there.

```
dt-sdk build . --python-version 3.14 -e manylinux2014_x86_64 -e win_amd64
```

The signed `.zip` is written to the `dist/` folder.

### 3. Upload to Dynatrace

1. In Dynatrace open **Extensions** (Hub) > **Manage extensions** > **Upload custom Extensions 2.0 extension**.
2. Select the `.zip` from `dist/`.
3. Open the uploaded extension (`custom:software-inventory`) and choose **Add monitoring configuration**.

### 4. Configure monitoring

Choose the host(s) or host group to monitor, then set the (optional) parameters:

| Parameter | Description | Default |
|---|---|---|
| `collection_interval` | How often to collect installed programs, in minutes | `60` |
| `registry_path_64bit` | Windows registry path for 64-bit programs | `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` |
| `registry_path_32bit` | Windows registry path for 32-bit programs | `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` |
| `exclude_windows_updates` | Skip `KB…` update entries (`true`/`false`) | `true` |

### 5. Verify data is arriving

After one collection interval, run in a Notebook:

```dql
timeseries count = max(software_inventory.programs.info, scalar:true), by:{host.name, program_name, program_version}
| sort program_name asc
```

Or check the extension's **Status** in the monitoring configuration and the OneAgent extension logs if nothing shows.

### 6. Import the dashboards

1. Go to **Dashboards** > **Upload**.
2. Upload [Software_Inventory_Fleet_Overview.json](Software_Inventory_Fleet_Overview.json) and [Software_Inventory_Host_Detail.json](Software_Inventory_Host_Detail.json).

Or with dtctl: `dtctl apply -f Software_Inventory_Fleet_Overview.json`

## Local development

* Run in simulation mode: `dt-sdk run` (uses [activation.json](activation.json))
* Lint: `ruff check .`
* Increase the version in [extension/extension.yaml](extension/extension.yaml) after every change, then rebuild.

## Repository structure

| Path | Purpose |
|---|---|
| `software_inventory/` | Python code for the extension |
| `extension/` | `extension.yaml` and activation definitions |
| `setup.py` | Dependencies and Python metadata |
| `activation.json` | Activation definition used for local simulation only |
| `*.json` (root) | Dashboard exports |

## Troubleshooting

- **No data** – confirm the monitoring configuration is assigned to the host and OneAgent has the extension ("Python extension" status in the host's extensions list).
- **Unsupported Linux distribution** – only ubuntu, debian, centos, rhel and fedora are recognised.
- **Linux package list empty** – make sure `dpkg-query` or `rpm` is on the OneAgent user's `PATH`.
