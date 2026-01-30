# NetGuard Security Scanner

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Security](https://img.shields.io/badge/Type-Network%20Security-red)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

### 🛡️ Overview
**NetGuard** is a lightweight, automated network reconnaissance and vulnerability assessment tool. Designed for network administrators and security researchers, it combines active device discovery with deep packet analysis to identify potential security risks within a Local Area Network (LAN).

Unlike standard scanners that simply list open ports, NetGuard includes a **Risk Recommendation Engine** that interprets results and provides actionable security advice (e.g., warning about unencrypted Telnet/FTP or exposed SMB ports).

---

### 🚀 Key Features

* **🕵️ Smart Device Discovery:**
    * Utilizes a hybrid scan engine (Broadcast Ping + System ARP Cache) to stealthily identify all connected assets (PCs, Mobile, IoT).
    * Bypasses typical Layer 2 blocks that stop standard Python scanners.

* **🏷️ Automated Vendor Recognition:**
    * Instantly resolves MAC addresses to Manufacturer names (Apple, Intel, Dell, etc.) for rapid asset classification.

* **⚔️ Vulnerability Analysis & Advice:**
    * **Port Scanning:** Multi-threaded TCP connect scan for critical services (HTTP, SSH, RDP, MySQL, etc.).
    * **Banner Grabbing:** Automatically extracts server headers (e.g., `lighttpd/1.4.39`) from open web ports.
    * **Security Advisor:** Automatically flags dangerous ports (e.g., 23, 445) and provides specific remediation steps in real-time.

* **📊 Live Dashboard:**
    * Professional Dark Mode GUI (Tkinter) for real-time visualization of network data.

---

### 🛠️ Technology Stack
* **Core Logic:** Python 3.12
* **Networking:** `socket`, `requests`, `os` (System Integration)
* **Interface:** `tkinter` (Native GUI)
* **Data Parsing:** `re` (Regex), `threading` (Concurrency)

---

### 💻 Installation & Usage

#### Option 1: Standalone Executable (Windows)
1.  Download the latest `NetGuard_Scanner.exe` from the releases page.
2.  Run as Administrator (required for full network visibility).
3.  Click **"START SCAN"** to begin discovery.

#### Option 2: Run from Source
1.  Clone the repository:
    ```bash
    git clone [https://github.com/alkahaleemad/NetGuard.git](https://github.com/alkahaleemad/NetGuard.git)
    ```
2.  Install dependencies:
    ```bash
    pip install requests mac-vendor-lookup
    ```
3.  Launch the tool:
    ```bash
    python dashboard.py
    ```

---

### 👤 Developer
**Emad**
* **Major:** Security & Network
* **University:** Ajman University

---

### ⚠️ Legal Disclaimer

This tool is designed for educational purposes and authorized network administration only. Scanning networks without permission is illegal. The developer is not responsible for misuse of this tool.

