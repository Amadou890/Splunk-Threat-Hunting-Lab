# 🛡️ Threat Hunting & Incident Response Lab: Splunk & Sysmon Log Analysis

## 📌 Executive Summary
This project demonstrates a hands-on threat hunting and incident investigation workflow using **Splunk Enterprise**. The scenario simulates an end-to-end investigation of an adversary gaining initial access, executing living-off-the-land (LotL) binaries, establishing persistence, and attempting lateral movement within an enterprise domain.

All attack phases were mapped directly to the **MITRE ATT&CK Framework** to document root causes, Indicators of Compromise (IOCs), and technical remediation strategies.

---

## 🛠️ Tools & Data Sources
 
| Category | Details |
|:--|:--|
| SIEM | Splunk (searched email and firewall logs) |
| Threat intelligence | TryDetectThis (IP / URL / domain reputation) |
| Log sources | Email logs, firewall logs |
| Reference material | Scenario documentation: alert classification rules, reporting template, employee and asset tables |
| Framework | MITRE ATT&CK (techniques below) |
 
---
 
## 🔍 Triage Workflow
 
For every alert I followed the same process:
 
1. **Take ownership** of the alert in the queue so it isn't worked twice.
2. **Read the alert description.** It states what to check (here, always: *did anyone access the link, and was it allowed or blocked?*).
3. **Identify the people and hosts** involved using the scenario's employee table (email → user → host → IP).
4. **Search Splunk** for the sender, domain, URL, and source/destination IPs to build the timeline across email and firewall logs.
5. **Check indicators** (destination IPs) in TryDetectThis. A clean result only means "not known to be malicious," so I weighed it against the logs.
6. **Classify** as true positive (TP) or false positive (FP).
7. **Decide on escalation** for true positives: did anything reach the user, and is further action (password reset, account review) needed?
8. **Write the case report** covering who, what, when, where, and why.
---
 
## 📋 Alerts Handled
 
| Alert ID | Alert | Key evidence | Classification | Escalate? |
|:--|:--|:--|:--|:--|
| **#8814** | Inbound email with external link (`onboarding@hrconnex.thm`) | Internal email from Human Resources to IT Support confirmed `hrconnex.thm` is the company's new third-party HR partner and that the recipient was expecting the onboarding email. No firewall connection to the link. | **False Positive** | N/A |
| **#8815** | Inbound email: fake Amazon delivery notice (`urgents@amazon.biz`, bit.ly link) | Sender domain is not Amazon's, generic greeting, shortened link, 48-hour pressure. Recipient's host (`10.20.2.17`) clicked the link; firewall **blocked** the connection under the `Blocked Websites` rule. Only one employee received the email. | **True Positive** | **No**: blocked before anything loaded |
| **#8816** | Access to blacklisted external URL blocked by firewall | Same bit.ly link as #8815, the other half of the same incident. Destination IP `67.199.248.11` reported **malicious** in TryDetectThis. Only one blocked connection to that destination. | **True Positive** | **No**: blocked, nothing reached the host |
| **#8817** | Inbound email: fake Microsoft sign-in alert (`no-reply@m1crosoftsupport.co`) | Lookalike domain (number "1" in place of the letter "i"). Recipient's host (`10.20.2.25`) connected to the fake login page and the firewall **allowed** it. Destination IP `45.148.10.131` reported **malicious** in TryDetectThis. | **True Positive** | **Yes**: connection succeeded |
 
> Replace `#XXXX` with the alert ID from your **Case reports** tab in the simulator.
 
---
 
## 🚨 Deep Dive: The Escalated Case
 
The fake Microsoft email and the fake Amazon email are the same kind of attack, but they had different outcomes, and that difference is what changes the escalation decision.
 
| | Amazon phishing (#8815 / #8816) | Microsoft phishing (#XXXX) |
|:--|:--|:--|
| Lure | Package delivery problem | Unusual sign-in warning |
| Link | Shortened bit.ly URL | Lookalike domain `m1crosoftsupport.co` |
| User clicked? | Yes | Yes |
| Firewall action | **Blocked** (`Blocked Websites`) | **Allowed** (`Allow-Internet`) |
| Reached user? | No | **Yes**, the fake login page loaded |
| Escalate? | No | **Yes** |
 
**Why escalate:** The logs show the user's machine reached the fake login page, but they can't show whether she typed in her password. If she did, the attacker has working credentials. Further action is needed, so this alert goes up rather than being closed out.
 
**Recommended remediation (in the case report):**
- Reset the affected user's password and revoke active sessions
- Review the account's sign-in history for activity the user doesn't recognize
- Block `m1crosoftsupport.co` and `45.148.10.131` at the firewall / email gateway
- Check whether any other employee received email from the same sender domain
**Why the firewall missed it:** The firewall blacklist only covers *known* threats. A newly registered lookalike domain wasn't on it yet. This is why threat-intel lookups and log review matter beyond relying on preventive controls.
 
---
 
## 🧩 Indicators of Compromise (IOCs)
 
| Type | Indicator | Context |
|:--|:--|:--|
| Sender domain | `amazon.biz` | Fake Amazon delivery notice |
| URL | `http://bit.ly/3sHkX3da12340` | Shortened phishing link (blocked) |
| IP address | `67.199.248.11` | Destination of the bit.ly link; malicious per TryDetectThis |
| Sender domain | `m1crosoftsupport.co` | Lookalike Microsoft domain |
| URL | `https://m1crosoftsupport.co/login` | Fake sign-in page (allowed) |
| IP address | `45.148.10.131` | Destination of the fake login page; malicious per TryDetectThis |
 
---
 
## 🗺️ MITRE ATT&CK Mapping
 
| Tactic | Technique | Where it appeared |
|:--|:--|:--|
| Initial Access | [T1566.002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) | Amazon and Microsoft lure emails |
| Execution | [T1204.001: User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/) | Users clicked the links |
 
---
 
## 💡 What I Took Away
 
1. **Suspicious-looking isn't the same as malicious.** The first alert had every phishing hallmark (external sender, "Action Required," a link) and was legitimate. One search of internal email proved it.
2. **"Blocked" vs. "allowed" decides escalation.** Two alerts had the same attack pattern. The only difference was one word in a firewall log.
3. **Answer the question the alert asks.** Each alert description told me what to verify. Doing exactly that kept investigations short.
4. **Correlate across log sources.** Matching the email event to the firewall event is what turned two separate alerts into one story.
5. **Reports are for the next person.** Each report covered who, what, when, where, and why so a Tier-2 analyst could pick it up without redoing the work.
---
 
## ⚠️ Scope & Limitations
 
- This is a **guided training scenario** with scripted alerts and a closed set of logs, not a production SOC. It demonstrates triage reasoning and reporting, not tuning, detection engineering, or incident containment.
- Remediation steps are **recommendations written in the case reports**. The simulator doesn't let analysts take containment actions.
---
 
## 📁 Repository Structure
 
```
├── README.md          # This write-up
├── reports/           # My case reports for the alerts above
└── screenshots/       # Splunk searches, TryDetectThis results, simulator results screen
```
