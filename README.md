# NetScanner — Graphical Network Scanner Built on Nmap

**Author:** Jasim Alsulaiman

NetScanner is a lightweight, dependency-free **Java Swing** desktop application that runs **Nmap** in the background, lists live hosts with their open ports, services, and versions, and saves reports encrypted with **AES-256-GCM** (key derived from a password using **PBKDF2-HMAC-SHA256**).

> **Disclaimer:** Only scan networks and hosts that you own or have explicit authorization to test.

---

## Features
- **Automatic Network Detection:** Identifies your active non-virtual IPv4 interface and suggests your local `/24` subnet automatically.
- **Two Scan Modes:**
  - **Fast:** `nmap -sV -T4 -F` (top 100 ports, quicker)
  - **Slow (detailed):** `nmap -sV -T3` (top 1,000 ports, more detailed)
- **Live Output & Cancellable Scans:** Streams real-time Nmap output in the log pane with one-click cancellation.
- **Encrypted Reports (`.enc`):** Saves and opens scan reports using **AES-256-GCM** (PBKDF2-HMAC-SHA256, 100,000 iterations). Wrong passwords or modified files are automatically rejected.

---

## Requirements
- **Java JDK 8 or newer** (tested on OpenJDK 21 — [Eclipse Temurin 21 LTS](https://adoptium.net))
  - A JDK is needed to build from source; a JRE is enough to run a compiled `NetScanner.jar`.
- **Nmap 7.x** (tested on Nmap 7.94 — [nmap.org/download.html](https://nmap.org/download.html))
  - On Windows, keep **Npcap** checked during installation.

Verify both in your terminal:
```bash
java -version
nmap --version
```

---

## Project Structure
```text
src/netscanner/       Java source code (10 classes)
test/netscanner/      SelfTest.java (automated self-test)
build.bat / build.sh  Compile the sources into NetScanner.jar
run.bat / run.sh      Build (if needed) and launch the GUI
README.md             Documentation
```

---

## Quick Start

**Windows:**
```cmd
git clone [https://github.com/jasimalsulaiman-cloud/](https://github.com/jasimalsulaiman-cloud/)
