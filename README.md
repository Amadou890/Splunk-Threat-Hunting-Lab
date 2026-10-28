# 🛡️ Threat Hunting & Incident Response Lab: Splunk & Sysmon Log Analysis

## 📌 Executive Summary
This project demonstrates a hands-on threat hunting and incident investigation workflow using **Splunk Enterprise** and **Windows Sysmon telemetry**. The scenario simulates an end-to-end investigation of an adversary gaining initial access, executing living-off-the-land (LotL) binaries, establishing persistence, and attempting lateral movement within an enterprise domain.

All attack phases were mapped directly to the **MITRE ATT&CK Framework** to document root causes, Indicators of Compromise (IOCs), and technical remediation strategies.

---

## 🛠️ Tools & Technologies
- **SIEM:** Splunk Enterprise / SPL (Search Processing Language)
- **Endpoint Telemetry:** Windows Event Logs, Sysmon (System Monitor)
- **Frameworks:** MITRE ATT&CK Framework
- **Analysis Tools:** Command Line Interface (CLI), Wireshark (PCAP Analysis)
- **OS Environments:** Windows 10/11 Enterprise, Linux/Bash

---

## 🔍 Investigation Chronology & MITRE ATT&CK Mapping

### 1. Initial Access & Execution
- **MITRE Technique:** [T1059.001 - Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- **Investigation:** Queried Sysmon **Event ID 1** (Process Creation) in Splunk to isolate suspicious execution of `powershell.exe` launching obfuscated base64 encoded payloads.
- **SPL Query:**
  ```spl
  index=wineventlog EventCode=1 Image="*powershell.exe" | table _time, host, User, CommandLine, ParentImage
