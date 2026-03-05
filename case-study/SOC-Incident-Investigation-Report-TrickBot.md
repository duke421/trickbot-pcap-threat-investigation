# SOC Incident Investigation Report
## TrickBot Malware Delivery via Masqueraded PE File

---

| Field | Details |
|---|---|
| **Report ID** | INC-2024-0019 |
| **Classification** | CONFIDENTIAL |
| **Severity** | HIGH |
| **Status** | Closed – Remediated |
| **Analyst** | Gbemisola Faith Akinlabi |
| **Date of Detection** | February 2024 |
| **Date of Report** | March 2024 |
| **Tools Used** | Wireshark, VirusTotal, GHex |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Detection](#2-detection)
3. [Affected Systems](#3-affected-systems)
4. [Investigation](#4-investigation)
5. [Key Findings](#5-key-findings)
6. [Indicators of Compromise](#6-indicators-of-compromise)
7. [Attacker Behaviour Analysis](#7-attacker-behaviour-analysis)
8. [MITRE ATT&CK Mapping](#8-mitre-attck-mapping)
9. [Containment and Response](#9-containment-and-response)
10. [Lessons Learned](#10-lessons-learned)
11. [Conclusion](#11-conclusion)

---

## 1. Executive Summary

A security alert was raised following suspicious outbound network activity observed on a Windows host within the internal network. Analysis of a provided PCAP capture confirmed that the host (`DESKTOP-M1TFHB6`, IP `10.8.19.101`) had downloaded a file disguised as a PDF from an external IP address (`185.244.41.29`) using the `curl` command-line utility — a strong indicator of scripted or automated execution rather than legitimate user browsing.

Forensic inspection of the extracted file revealed that despite carrying a `.pdf` extension, the file contained a Windows Portable Executable (PE) header (`MZ / 4D 5A`), identifying it as a disguised Dynamic Link Library (`ooiwdy.dll`). Submission to VirusTotal confirmed the file as **TrickBot**, a well-known banking trojan with capabilities spanning credential theft, lateral movement, and ransomware staging.

Network analysis further identified a `POST` request from the infected host to a second external IP (`103.148.41.195`), consistent with Command and Control (C2) communication exfiltrating victim system data. The compromised user account identified during investigation was `monica.steele`.

This report documents the full investigation workflow, all identified IOCs, attacker behaviour mapping, and the recommended containment and hardening actions.

---

## 2. Detection

**Initial Trigger:** Anomalous outbound HTTP traffic observed in PCAP capture associated with internal host `10.8.19.101`.

During review of captured network traffic, the following suspicious activity was identified:

- An internal host (`10.8.19.101`) issued a `GET` request over HTTP to an external IP address (`185.244.41.29`) requesting a file named `ooiwy.pdf`.
- The `User-Agent` string within the HTTP request header was `curl/7.55.1` — strongly suggesting the download was initiated by an automated script or a command-line call rather than a web browser, which is abnormal for a standard user workstation.
- A subsequent `POST` request was observed from the same internal host to a different external IP (`103.148.41.195`), indicating data exfiltration or C2 beacon activity.
- TCP stream reconstruction confirmed the POST body contained host-specific system information, consistent with TrickBot's reconnaissance and check-in behaviour.

These indicators collectively formed a high-confidence signal of malware activity, prompting a full investigation.

---

## 3. Affected Systems

| Field | Value |
|---|---|
| **Hostname** | `DESKTOP-M1TFHB6` |
| **Internal IP Address** | `10.8.19.101` |
| **MAC Address** | `00-08-02-1C-47-AE` |
| **User Account** | `monica.steele` |
| **Operating System** | Windows (confirmed via NTLMSSP and SMB traffic) |
| **Role** | User Workstation |

---

## 4. Investigation

The investigation was conducted through systematic analysis of the provided PCAP file using Wireshark, GHex, and VirusTotal.

### 4.1 Host Identification

**Hostname Recovery — DHCP and SMB Filtering**

To identify the affected host, two Wireshark display filters were applied in sequence:

- **`dhcp`** filter: Examined DHCP traffic to extract the hostname advertised by the client during lease negotiation. DHCP `REQUEST` packets confirmed the hostname `DESKTOP-M1TFHB6`.
- **`smb`** filter: Applied as a secondary confirmation method. SMB session negotiation packets and NetBIOS name service queries corroborated the hostname.
- **HTTP stream follow**: Following the HTTP stream provided a third confirmation of the hostname embedded within HTTP headers.

**IP Address Recovery — HTTP Filtering**

Using the **`http`** display filter, HTTP traffic was isolated to identify communicating hosts. The source IP `10.8.19.101` was confirmed as the internal infected workstation, with outbound requests directed to external destinations `185.244.41.29` and `103.148.41.195`.

**MAC Address Recovery — ARP Filtering**

With the IP address confirmed, an **`arp`** display filter was applied to ARP broadcast traffic. The ARP reply packets mapped IP `10.8.19.101` to MAC address `00-08-02-1C-47-AE`, positively identifying the physical network interface of the infected machine.

**User Account Recovery — NTLMSSP Filtering**

The **`ntlmssp`** display filter was applied to isolate Windows authentication packets. NTLM authentication exchanges transmitted in cleartext within the PCAP revealed the authenticated user account: `monica.steele`. NTLMSSP packets frequently carry usernames during Windows domain authentication and file share access, making this a reliable extraction method.

---

### 4.2 Network Traffic Analysis

With host details confirmed, the investigation proceeded to deep traffic analysis.

**Step 1 — HTTP Object Export**

The `http` display filter was re-applied to review all HTTP-layer communications. Wireshark's `File > Export Objects > HTTP` function was used to extract all transferred files from the PCAP. The file `ooiwy.pdf` was identified as an object transferred during the session and was exported for forensic analysis.

**Step 2 — File Signature Inspection (GHex)**

The exported file `ooiwy.pdf` was opened in GHex (hex editor) to inspect its binary header. The first two bytes of the file were identified as:

```
4D 5A
```

This is the **MZ magic number** — the Windows Portable Executable (PE) header signature, named after MS-DOS developer Mark Zbikowski. The presence of this signature in a file advertised as a `.pdf` immediately confirmed that the file was **misrepresenting its true type**. PE files with this header can include `.exe`, `.dll`, and `.sys` formats.

**Step 3 — True File Format Identification**

Further inspection of the file's binary structure confirmed that the original file format was `ooiwdy.dll` — a Windows Dynamic Link Library (DLL). DLL masquerading is a common technique used by malware authors to bypass basic file type inspection and evade user suspicion.

**Step 4 — VirusTotal Submission**

The extracted file was submitted to VirusTotal for multi-engine reputation analysis. The scan returned a high-confidence positive detection:

- **Classification:** Trojan
- **Family:** TrickBot
- **Detection Ratio:** Flagged by multiple antivirus engines
- **File Hashes confirmed** (see IOC section)

VirusTotal output confirmed the file signature matched known TrickBot DLL payloads.

**Step 5 — C2 Communication Analysis (TCP Stream Reconstruction)**

Returning to the PCAP, a `POST` request from `10.8.19.101` to the external IP `103.148.41.195` was identified in the HTTP traffic logs. Following the TCP stream for this request revealed the POST body contained structured victim system data — consistent with TrickBot's initial beacon to its Command and Control infrastructure, transmitting host reconnaissance data including system details and user information.

---

## 5. Key Findings

- A Windows workstation (`DESKTOP-M1TFHB6 / monica.steele`) downloaded a malicious PE file disguised as a PDF from `185.244.41.29` using `curl`, indicating scripted execution.
- The file `ooiwy.pdf` was confirmed as a TrickBot DLL payload (`ooiwdy.dll`) through hex signature analysis (MZ header: `4D 5A`).
- The malware established C2 communication with `103.148.41.195`, transmitting host reconnaissance data via HTTP POST.
- The `curl/7.55.1` User-Agent string confirms the download was not initiated via a browser, suggesting an execution mechanism such as a malicious script, macro, or dropped loader.
- The infected host had active Windows authentication sessions (`monica.steele`) at the time of infection, meaning credentials may have been accessible to TrickBot's credential harvesting module.

---

## 6. Indicators of Compromise

### 6.1 Affected Host

| Attribute | Value |
|---|---|
| Hostname | `DESKTOP-M1TFHB6` |
| IP Address | `10.8.19.101` |
| MAC Address | `00-08-02-1C-47-AE` |
| User Account | `monica.steele` |

### 6.2 Malicious Network Indicators

| Type | Value | Role |
|---|---|---|
| Malicious IP | `185.244.41.29` | Malware Delivery Server |
| Malicious IP | `103.148.41.195` | Command and Control (C2) Server |
| HTTP Method | `GET` | File download from delivery IP |
| HTTP Method | `POST` | Victim data exfiltrated to C2 IP |
| User-Agent | `curl/7.55.1` | Scripted download indicator |

### 6.3 Malicious File

| Attribute | Value |
|---|---|
| Filename (as delivered) | `ooiwy.pdf` |
| True Filename | `ooiwdy.dll` |
| True File Type | Windows DLL (PE executable) |
| File Signature | `4D 5A` (MZ header) |
| Malware Family | TrickBot |
| Malware Type | Trojan |
| MD5 | `4e4ae70b6346eae111e31716dc76bc23` |
| SHA-1 | `1e7b9af799048e4112d2468323c5c147e20558f9` |
| SHA-256 | `f25a780095730701efac67e9d5b84bc289afea56d96d8aff8a44af69ae606404` |

---

## 7. Attacker Behaviour Analysis

### 7.1 Initial Access and Delivery

The malware was delivered via an HTTP `GET` request originating from the internal host, using the `curl` utility with User-Agent `curl/7.55.1`. This suggests the download was triggered by a previously executed component — such as a malicious script, Office macro, or a dropper — rather than direct user action. The delivery server (`185.244.41.29`) served the payload disguised as a PDF file to evade cursory file inspection.

### 7.2 Masquerading

The payload `ooiwy.pdf` carried a `.pdf` extension to deceive users and bypass file-type-based controls. Binary inspection confirmed the file was in fact a Windows DLL (`ooiwdy.dll`) with an MZ PE header. This is a classic extension-spoofing technique used by TrickBot and similar loaders to evade detection during delivery.

### 7.3 Execution

The use of `curl` as the download mechanism is consistent with execution from a script or command-line loader running under the `monica.steele` user context. TrickBot is commonly staged as a DLL, loaded via `rundll32.exe` or a similar native Windows mechanism following download.

### 7.4 Command and Control (C2) Communication

Following execution, the malware established C2 communication with `103.148.41.195` via HTTP `POST`. The reconstructed TCP stream confirmed the POST body contained host system information, consistent with TrickBot's initial check-in phase where victim telemetry — including system details, user accounts, and network configuration — is transmitted to the C2 infrastructure. This marks the transition from infection to active attacker control.

### 7.5 Likely Follow-On Objectives

Based on TrickBot's known capabilities and the confirmed C2 beacon, the following post-compromise actions were likely intended:

- **Credential harvesting:** TrickBot is known to target saved browser credentials, Windows credentials, and Active Directory data.
- **Lateral movement:** TrickBot can enumerate and propagate across Windows networks using SMB exploits and credential reuse.
- **Ransomware staging:** TrickBot has historically been used as a precursor to Ryuk and Conti ransomware deployments.
- **Banking fraud:** TrickBot's original capability involves web injection to intercept banking sessions.

---

## 8. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Initial Access | T1566 | Phishing | Likely phishing vector triggered the scripted download |
| Execution | T1059 | Command and Scripting Interpreter | `curl` used to execute file download from CLI |
| Defence Evasion | T1036.007 | Masquerading: Double File Extension | `ooiwy.pdf` delivered as DLL with misleading extension |
| Defence Evasion | T1027 | Obfuscated Files or Information | PE binary disguised with PDF filename |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP used for C2 POST communication |
| Command and Control | T1105 | Ingress Tool Transfer | Payload downloaded via HTTP GET from external IP |
| Discovery | T1082 | System Information Discovery | Host data transmitted in C2 POST body |
| Discovery | T1033 | System Owner/User Discovery | User account `monica.steele` identified in exfiltrated data |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Victim data POSTed to `103.148.41.195` over HTTP |
| Credential Access | T1555 | Credentials from Password Stores | TrickBot known to harvest credentials post-execution |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | TrickBot propagates via SMB; SMB traffic observed in PCAP |

---

## 9. Containment and Response

### Immediate Actions (0–4 Hours)

- **Isolate the host:** Immediately disconnect `DESKTOP-M1TFHB6` (IP `10.8.19.101`) from the network to prevent further lateral movement or C2 communication.
- **Block malicious IPs at the firewall/proxy:** Add deny rules for `185.244.41.29` (delivery server) and `103.148.41.195` (C2 server) across all network egress points.
- **Disable the compromised user account:** Suspend `monica.steele` immediately and force a password reset for all accounts that may share credentials or be accessible from the infected host.
- **Preserve forensic evidence:** Capture a full memory dump and disk image from `DESKTOP-M1TFHB6` prior to remediation for deeper forensic analysis.

### Short-Term Actions (4–72 Hours)

- **Scan all endpoints:** Deploy an IOC-based scan across the environment using the confirmed file hashes (MD5, SHA-1, SHA-256) and the filenames `ooiwy.pdf` / `ooiwdy.dll` to identify any additional infected systems.
- **Hunt for lateral movement:** Search authentication logs and SMB traffic logs for connections originating from `10.8.19.101` to other internal hosts during the period of compromise.
- **Review `curl` and scripted HTTP download activity:** Query endpoint detection logs for other instances of `curl`, `wget`, or `bitsadmin` being used to download files from external IPs on non-standard user workstations.
- **Credential reset:** Assume all credentials accessible from `monica.steele`'s session are compromised. Enforce a full credential reset for the affected user and review Active Directory for signs of account enumeration.
- **Review and update DNS/proxy blocklists:** Ensure the malicious IPs and any associated domains are added to DNS sinkholes, proxy deny lists, and threat intelligence feeds.

### Detection Rule Improvements

Add or update the following detections in SIEM / IDS / EDR:

- **Alert on `curl` or `wget` User-Agent strings** from internal workstation IPs in HTTP proxy logs.
- **Alert on PE files delivered with non-executable extensions** (e.g., `.pdf`, `.docx`) using file signature inspection at the proxy or email gateway.
- **Alert on HTTP POST requests** from internal hosts to external IPs containing structured system data patterns.
- **Alert on outbound connections** to `185.244.41.29` and `103.148.41.195`.
- **Alert on file hash matches** for the confirmed TrickBot DLL across endpoint telemetry.

---

## 10. Lessons Learned

### What Went Wrong

- **Endpoint protection did not prevent the malware download.** The masqueraded DLL (`ooiwy.pdf`) bypassed any file-type controls that relied on extension alone rather than binary signature inspection.
- **Scripted downloads using `curl` were not alerted on.** Workstations should not be using `curl` to download files from external IPs; this behaviour was not flagged in real time.
- **No egress filtering was in place** to prevent the infected host from successfully communicating with the C2 server (`103.148.41.195`) and transmitting victim data.
- **No network-level file inspection** was in place to detect PE files masquerading as PDFs at the perimeter.

### Security Improvements

- **Deploy deep packet inspection (DPI)** at the network perimeter to inspect file signatures in transit and block PE files regardless of extension.
- **Restrict command-line download tools** on user workstations. `curl`, `wget`, and `certutil` should be blocked or monitored via application control policies (e.g., AppLocker or Windows Defender Application Control).
- **Implement DNS-layer filtering** (e.g., Cisco Umbrella, Cloudflare Gateway) to block outbound connections to known malicious IPs and domains before a TCP connection is established.
- **Enable multi-factor authentication (MFA)** for all user accounts to limit the impact of credential theft.
- **Conduct phishing awareness training** — TrickBot is commonly delivered through phishing emails, and user awareness is a critical first line of defence.
- **Deploy a Host-based Intrusion Detection System (HIDS)** to monitor for anomalous process behaviour including DLL injection, LSASS access, and unusual outbound connections from workstations.
- **Review least-privilege policies.** Standard user accounts should not have the ability to execute downloaded DLLs or use scripting tools without administrative approval.

---

## 11. Conclusion

Analysis of the PCAP confirmed a successful TrickBot malware infection on workstation `DESKTOP-M1TFHB6` (`10.8.19.101`), under the user account `monica.steele`. The attack chain involved a scripted download of a disguised DLL payload (`ooiwy.pdf` → `ooiwdy.dll`) from a malicious delivery server, followed by active C2 communication that exfiltrated host reconnaissance data.

The investigation successfully identified all key host attributes, reconstructed the infection chain, confirmed the malware family through file signature analysis and threat intelligence, and mapped the attacker's behaviour to MITRE ATT&CK techniques. All IOCs have been documented and are ready for ingestion into threat intelligence platforms and SIEM detection rulesets.

Immediate containment actions, including host isolation, IP blocking, and credential reset, should be executed without delay. Longer-term hardening improvements — particularly around perimeter file inspection, egress filtering, and endpoint application control — are essential to preventing recurrence of this attack pattern.

---

*Report authored by Gbemisola Faith Akinlabi | SOC Analyst*
*Investigation conducted using: Wireshark · VirusTotal · GHex*
*All findings are based on forensic analysis of the supplied PCAP capture file.*
