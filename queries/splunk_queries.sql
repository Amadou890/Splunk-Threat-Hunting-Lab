================================================================================
THREAT HUNTING & SOC SIMULATION: SPLUNK & SYSMON QUERY BOOK
Analyst: Amadou Barry
Repository: Splunk-Threat-Hunting-Lab
Method: Direct SIEM Investigation & Telemetry Correlation
================================================================================
*/
 
/*
--------------------------------------------------------------------------------
1. EXECUTION: POWERSHELL PROCESS CREATION (Sysmon Event ID 1)
--------------------------------------------------------------------------------
* Description: Monitors process creation events. Attackers often leverage built-in
  binaries (LolBins) or obfuscated script interpreters like PowerShell to execute payloads.
* Analyst Focus: Query 1a lists every PowerShell execution. Review the results for unusual
  parent-child process relationships (e.g., winword.exe spawning powershell.exe) and command
  lines containing base64 encoding or hidden flags. Query 1b (optional) filters for those flags.
* MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell)
--------------------------------------------------------------------------------
*/
 
-- 1a. All PowerShell executions
index=wineventlog EventCode=1 Image="*powershell.exe"
| table _time, host, User, CommandLine, ParentImage, ProcessId
| sort - _time
 
-- 1b. (OPTIONAL, untested) Encoded or hidden PowerShell only
-- Tip: -EncodedCommand values are base64 over UTF-16LE text (CyberChef: From Base64 -> Decode text UTF-16LE)
index=wineventlog EventCode=1 Image="*powershell.exe"
    (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-nop*"
     OR CommandLine="*-w hidden*" OR CommandLine="*-WindowStyle Hidden*")
| table _time, host, User, CommandLine, ParentImage, ProcessId
| sort - _time
 
/*
--------------------------------------------------------------------------------
2. PERSISTENCE MECHANISMS: REGISTRY RUN KEYS (Sysmon Event ID 13)
--------------------------------------------------------------------------------
* Description: Tracks registry value modifications. Threat actors frequently create
  or alter Run keys under the Windows Registry to ensure persistence across reboots.
* Analyst Focus: Identify newly created or modified registry entries pointing to
  temporary directories, user AppData folders, or anomalous executable paths.
* MITRE ATT&CK: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)
--------------------------------------------------------------------------------
*/
 
index=wineventlog EventCode=13 TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
| table _time, host, User, TargetObject, Details
| sort - _time
 
/*
--------------------------------------------------------------------------------
3. COMMAND & CONTROL (C2): NON-STANDARD PORT CONNECTIONS (Sysmon Event ID 3)
--------------------------------------------------------------------------------
* Description: Logs network connection events initiated by processes on the endpoint.
* Analyst Focus: Detect outbound connections to suspicious external IP addresses and
  unusual ports (e.g., TCP 4444, 1337).
* Limitation: Query 3a hardcodes port 4444 (the default Metasploit listener port). It catches
  lab-style activity but will miss C2 traffic on any other port.
* MITRE ATT&CK: T1571 (Non-Standard Port) / T1071 (Application Layer Protocol)
--------------------------------------------------------------------------------
*/
 
-- 3a. Connections to port 4444
index=wineventlog EventCode=3 DestinationPort=4444
| table _time, host, SourceIp, DestinationIp, DestinationPort, Image
| sort - _time
 
/*
--------------------------------------------------------------------------------
3b. DISCOVERY: INTERNAL PORT SCANNING (Sysmon Event ID 3)  (OPTIONAL, untested)
--------------------------------------------------------------------------------
* Description: One process contacting many distinct ports or hosts in a short window.
* Analyst Focus: Compromised hosts scanning the internal network. Thresholds below are
  arbitrary starting points; tune them against a baseline. Vulnerability scanners and
  inventory tools will also trigger this.
* MITRE ATT&CK: T1046 (Network Service Discovery)
--------------------------------------------------------------------------------
*/
 
index=wineventlog EventCode=3
| bin _time span=5m
| stats dc(DestinationPort) as unique_ports, dc(DestinationIp) as unique_hosts by _time, host, Image
| where unique_ports>20 OR unique_hosts>10
| sort - unique_ports
 
/*
--------------------------------------------------------------------------------
4. DEFENSE EVASION: LOG CLEARING / TAMPERING (Windows Security Log Event ID 1102)
--------------------------------------------------------------------------------
* Description: Detects when the Security audit log is cleared by an administrator or intruder.
  (Event ID 104 is the equivalent when other logs, such as System, are cleared.)
* Analyst Focus: A cleared security log is a strong indicator of an adversary attempting
  to cover their tracks after performing post-exploitation activities.
* Note: Account field names for this event vary by how the logs were ingested, so Message is
  included to show who cleared the log even if User / Signature come back empty.
* MITRE ATT&CK: T1070.001 (Indicator Removal: Clear Windows Event Logs)
--------------------------------------------------------------------------------
*/
 
index=wineventlog EventCode=1102
| table _time, host, User, Signature, Message
| sort - _time
 
