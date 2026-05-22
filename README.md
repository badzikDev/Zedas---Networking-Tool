# Zedas (zedas)

Zedas is a lightweight, localized network asset tracking and live capture utility built for Linux environments. It continuously listens to network traffic to discover active hardware assets, safely mapping local IP identities to physical MAC addresses while actively monitoring network activity volume.

The application relies on `scapy` for core packet decoding/injection routines and uses the `click` framework to provide a clean, modular command-line tool structure.

---

## Features

* **Passive Network Sniffing:** Hooks directly into the system's socket layer to transparently intercept local packet headers.
* **Active ARP Scanning:** Runs a concurrent background worker thread to dynamically sweep subnets, forcing active devices to re-verify their presence.
* **Smart Identity Management:** Employs protective validation filtering to prevent Layer 2/3 IP flapping and rejects public cloud/external WAN destination IPs to ensure your tracking database stays completely clean.
* **Live Command Dashboard:** Split-execution capabilities allow you to keep the listener running in the background while querying local database snapshots instantly from a separate terminal.
* **Persistent Cache Sync:** Automatically flushes inventory tracking modifications down to a safe JSON data layer on disk (`~/.zedas_inventory.json`).

---

## Prerequisites

* **OS:** Linux (Ubuntu, Debian, Fedora, Arch, etc.)
* **Python:** Python 3.7+ installed along with `pip` and `venv`
* **Privileges:** Because the utility binds to raw network sockets to track assets, execution requires root (`sudo`) permissions.

---

## Universal Installation

Zedas includes a robust, automated installation script designed to handle system packages, isolate application environments inside python virtual environments securely under `/opt/zedas/`, and handle system path configurations automatically.

To download and install the utility globally on your system, execute the following commands:

```bash
# 1. Clone the repository
git clone [https://github.com/badzikDev/Zedas---Networking-Tool.git](https://github.com/badzikDev/Zedas---Networking-Tool.git)
cd Zedas---Networking-Tool

# 2. Run the global system installer
sudo ./installer.sh
