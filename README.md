# 🛡️ Windows Registry Change Monitoring System

A Python-based Digital Forensics & Incident Response (DFIR) tool that monitors the Windows Registry and detects suspicious or unauthorized modifications in real time.

This project was developed as part of the **Unified Mentor Cybersecurity Internship**.

---

## 📌 Overview

The Windows Registry is a critical component of the operating system and is often targeted by malware for:

- Persistence (autorun entries)
- Defense evasion (disabling Defender/Firewall)
- Privilege escalation (UAC bypass)
- System configuration manipulation

This tool helps detect such activities using **baseline comparison, behavior analysis, and risk scoring**.

---

## 🚀 Features

- 🔍 Detects **ADDED, MODIFIED, and DELETED** registry entries  
- 🧠 Monitors critical registry locations:
  - Autorun keys (Run / RunOnce)
  - Windows Defender settings
  - Firewall policies
  - UAC configuration
  - Winlogon shell  
- 🔐 **SHA-256 baseline integrity checking**  
- ⚠️ **Risk scoring engine** (LOW → MEDIUM → HIGH → CRITICAL)  
- 🧬 **Malware pattern detection**  
- 📡 **Real-time monitoring mode**  
- 📊 Generates detailed **forensic reports and logs**  
- ⚙️ Supports **Task Scheduler automation**

---

## 🧪 Test Scenarios Covered

The tool was tested using real-world attack simulations:

1. Persistence via autorun registry keys  
2. Suspicious executable path detection  
3. Registry entry deletion detection  
4. UAC (User Account Control) modification  
5. Firewall disable detection  
6. Windows Defender tampering detection

---

## ▶️ How to Run

Open PowerShell in the project directory and run:

### 1. Create Baseline

python registrymonitor.py --baseline
Creates a trusted registry snapshot.

## 2. Verify Integrity

python registrymonitor.py --check
Checks if registry matches the baseline.

## 3. Scan for Changes

python registrymonitor.py --scan
Detects added, modified, or deleted entries.

## 4. Monitor in Real-Time

python registrymonitor.py --monitor
Continuously monitors registry changes.

---

## ⚙️ Task Scheduler Automation

The monitoring tool can be automated using Windows Task Scheduler to run at scheduled intervals.

This allows continuous registry monitoring without manual execution, making it suitable for real-world security monitoring environments.

Example:
- Run the script every 5 minutes
- Monitor registry changes in the background
- Generate logs and reports automatically

For Example :
- Program: python
- Argument: registrymonitor.py --monitor

---

## ⚠️ Testing Note (Winlogon)

The Winlogon shell replacement scenario was not executed to avoid affecting system stability.

This ensures a safe testing environment while preventing disruption to normal system behavior.

---

## 📁 Project Structure

RegistryMonitor/
│
├── registrymonitor.py       # Main monitoring script
├── docs/                    # Documentation & presentation
├── reports/                 # Logs and forensic reports
├── screenshots/             # Testing and detection evidence
├── registry_baseline.json   # Baseline snapshot
├── registry_changes.log     # Change logs
└── registry_report.txt      # Final forensic report

---

## 📊 Sample Output

The tool generates:

📌 Change event logs (ADDED / MODIFIED / DELETED)

⚠️ Threat classification (e.g., Defense Evasion)

📈 Risk score and severity level

📄 Final forensic report

---


## 🧠 Key Concepts Used

Windows Registry Analysis

Digital Forensics Techniques

SHA-256 Hashing (Integrity Verification)

MITRE ATT&CK Mapping

Python (winreg, hashlib, json)

PowerShell for attack simulation

Task Scheduler for automation

---


## 🎯 Learning Outcomes

Through this project, I gained practical experience in:

Detecting malware-like registry behavior

Monitoring system configuration changes

Building forensic tools using Python

Understanding Windows internals and security mechanisms

---

## 👨‍💻 Author

**Sumit Dahiya (CDFE)**  
Certified Digital Forensics Examiner  
Unified Mentor Cybersecurity Internship  
   
