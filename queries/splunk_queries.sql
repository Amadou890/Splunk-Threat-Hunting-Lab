================================================================================
THREAT HUNTING & SOC SIMULATION: SPLUNK & SYSMON QUERY BOOK
Analyst: Amadou Barry
Repository: Splunk-Threat-Hunting-Lab
Method: Direct SIEM Investigation & Telemetry Correlation
================================================================================

/*
--------------------------------------------------------------------------------
1. INITIAL ACCESS & PROCESS EXECUTION (Sysmon Event ID 1)
--------------------------------------------------------------------------------
* Description: Monitors process creation events. Attackers often leverage built-in 
  binaries (LolBins) or obfuscated script interpreters like PowerShell to execute payloads.
* Analyst Focus: Look for unusual parent-child process relationships (e.g., winword.exe 
  spawning powershell.exe) and command lines containing base64 encoding or hidden flags.
* MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell)
--------------------------------------------------------------------------------
*/

index=wineventlog EventCode=1 Image="*powershell.exe" 
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
3. COMMAND & CONTROL (C2) & LATERAL MOVEMENT (Sysmon Event ID 3)
--------------------------------------------------------------------------------
* Description: Logs network connection events initiated by processes on the endpoint.
* Analyst Focus: Detect outbound connections to suspicious external IP addresses, 
  unusual ports (e.g., TCP 4444, 1337), or internal port scanning behavior across subnets.
* MITRE ATT&CK: T1046 (Network Service Discovery) / T1071 (Application Layer Protocol)
--------------------------------------------------------------------------------
*/

index=wineventlog EventCode=3 DestinationPort=4444 
| table _time, host, SourceIp, DestinationIp, DestinationPort, Image
| sort - _time


/*
--------------------------------------------------------------------------------
4. DEFENSE EVASION: LOG CLEARING / TAMPERING (Windows Security Log Event ID 1102)
--------------------------------------------------------------------------------
* Description: Detects when the Audit Log is cleared by an administrator or intruder.
* Analyst Focus: A cleared security log is a strong indicator of an adversary attempting 
  to cover their tracks after performing post-exploitation activities.
* MITRE ATT&CK: T1070.001 (Indicator Removal: Clear Windows Event Logs)
--------------------------------------------------------------------------------
*/

index=wineventlog EventCode=1102
| table _time, host, User, Signature
| sort - _time
