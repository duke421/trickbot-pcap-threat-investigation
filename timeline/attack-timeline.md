# Attack Timeline Reconstruction
## TrickBot Malware Infection — PCAP Network Traffic Analysis

---

| Field | Details |
|---|---|
| **Incident Reference** | INC-2024-0019 |
| **Analyst** | Gbemisola Faith Akinlabi |
| **Source** | PCAP network capture — Wireshark analysis |
| **Infected Host** | `DESKTOP-M1TFHB6` — `10.8.19.101` |
| **Malware Family** | TrickBot (Trojan) |
| **Delivery Server** | `185.244.41.29` |
| **C2 Server** | `103.148.41.195` |

---

## Introduction

This timeline was reconstructed from forensic analysis of a PCAP network capture file using Wireshark. Events are presented in chronological order based on packet timestamps recorded within the capture.

The timeline covers the full observed attack chain — from initial host activity on the network through to confirmed Command and Control (C2) communication and victim data exfiltration. Each event is mapped to the relevant network protocol, traffic observation, and attacker behaviour to support incident response, threat hunting, and post-incident review.

All timestamps are recorded in seconds relative to the start of the PCAP capture.

---

## Timeline Table

| Timestamp (s) | Phase | Event | Description |
|---|---|---|---|
| 0.000000 | Host Initialisation | DHCP Request Observed | Internal host `DESKTOP-M1TFHB6` broadcast a DHCP request on the network. The hostname `DESKTOP-M1TFHB6` was extracted from the DHCP `REQUEST` packet, providing the first host identifier in the capture. |
| 0.841337 | Host Initialisation | DHCP Lease Acknowledged | DHCP server issued a lease, assigning IP address `10.8.19.101` to host `DESKTOP-M1TFHB6`. This confirmed the internal IP address of the affected machine. |
| 1.203489 | Host Identification | ARP Broadcast Observed | Host `10.8.19.101` issued an ARP broadcast to announce its presence on the local network segment. ARP reply traffic confirmed the associated MAC address as `00-08-02-1C-47-AE`. |
| 3.571024 | Host Identification | SMB Session Negotiation | Server Message Block (SMB) protocol traffic was observed from `10.8.19.101`. SMB session negotiation and NetBIOS name service queries confirmed the hostname `DESKTOP-M1TFHB6` as a secondary verification. |
| 5.119843 | Credential Exposure | NTLMSSP Authentication Observed | NTLM Security Support Provider (NTLMSSP) authentication packets were captured. Analysis of the authentication exchange identified the active user account as `monica.steele`. The username was transmitted in cleartext within the NTLMSSP negotiation packet. |
| 72.622252 | Malware Delivery | Malicious File Downloaded | Host `10.8.19.101` sent an HTTP `GET` request to external IP `185.244.41.29` requesting the file `ooiwy.pdf`. The HTTP request header included a `User-Agent` string of `curl/7.55.1` — indicating the download was scripted or automated rather than initiated via a web browser. This is the primary malware delivery event. |
| 72.891045 | Malware Delivery | Payload Served by Delivery Server | External server `185.244.41.29` responded to the GET request and transferred the file `ooiwy.pdf` to the infected host. Despite the `.pdf` extension, binary inspection confirmed the file header contained the Windows PE magic bytes `4D 5A` (MZ), identifying it as a disguised Dynamic Link Library (`ooiwdy.dll`). VirusTotal confirmed the payload as **TrickBot** Trojan. |
| 95.429052 | Suspicious HTTP Communication | Continued Outbound HTTP Activity | The infected host `10.8.19.101` initiated further HTTP communication with the external IP `185.244.41.29`. This post-download activity is consistent with secondary payload retrieval, configuration fetching, or module loading — behaviours characteristic of TrickBot's modular architecture. |
| 312.774519 | System Reconnaissance | Malware Initiated Local Reconnaissance | Based on subsequent network activity patterns, TrickBot began host enumeration. This phase typically involves collecting system information including OS version, hostname, user accounts, domain membership, and network configuration — all of which were observed as data fields in the subsequent C2 POST body. |
| 373.903849 | Command and Control | C2 Beacon Transmitted | Host `10.8.19.101` transmitted an HTTP `POST` request to a second external IP `103.148.41.195` — a distinct server from the original delivery IP, consistent with TrickBot's infrastructure separation model. TCP stream reconstruction of the POST request confirmed the request body contained structured victim system information, indicating successful malware execution and active C2 communication. |
| 374.218763 | Data Exfiltration | Victim System Data Transmitted to C2 | The C2 POST body transmitted to `103.148.41.195` contained host reconnaissance data — including system identifiers, user account details, and network configuration. This confirmed the malware had successfully profiled the victim machine and reported back to attacker-controlled infrastructure, completing the initial infection and check-in cycle. |

---

## Attack Phase Summary

| Phase | Observed Behaviour | Attacker Infrastructure |
|---|---|---|
| **1. Host Initialisation** | DHCP lease, ARP broadcast, SMB negotiation | Internal network only |
| **2. Credential Exposure** | NTLMSSP authentication exposed `monica.steele` | Internal network only |
| **3. Malware Delivery** | Scripted HTTP GET for `ooiwy.pdf` (disguised DLL) | `185.244.41.29` |
| **4. Payload Execution** | PE file loaded despite PDF extension | Local host |
| **5. Secondary HTTP Activity** | Further outbound HTTP to delivery server | `185.244.41.29` |
| **6. System Reconnaissance** | TrickBot profiled host before C2 check-in | Local host |
| **7. C2 Communication** | HTTP POST beacon with victim data | `103.148.41.195` |
| **8. Data Exfiltration** | Structured host data transmitted to C2 | `103.148.41.195` |

---

## MITRE ATT&CK Timeline Mapping

| Timestamp (s) | MITRE Technique | Technique ID |
|---|---|---|
| 72.622252 | Ingress Tool Transfer | T1105 |
| 72.622252 | Masquerading: Double File Extension | T1036.007 |
| 72.622252 | Command and Scripting Interpreter | T1059 |
| 95.429052 | Application Layer Protocol: Web Protocols | T1071.001 |
| 312.774519 | System Information Discovery | T1082 |
| 312.774519 | System Owner/User Discovery | T1033 |
| 373.903849 | Application Layer Protocol: Web Protocols (C2) | T1071.001 |
| 374.218763 | Exfiltration Over C2 Channel | T1041 |

---

## Key Observations

- The `curl/7.55.1` User-Agent at `72.622252s` is the most critical early indicator — no standard user workstation should initiate file downloads via `curl`. This should have triggered an alert in any proxy or SIEM with a User-Agent anomaly rule.
- The **separation of delivery (`185.244.41.29`) and C2 (`103.148.41.195`) infrastructure** is consistent with TrickBot's known operational model, designed to make takedown of one server insufficient to disrupt the full operation.
- The **301-second gap** between the malware download (`72.622252s`) and the C2 beacon (`373.903849s`) represents the dwell time during which TrickBot executed, performed local reconnaissance, and prepared its initial check-in package.
- **No DNS queries** to resolve the attacker IPs were observed — communication occurred directly over IP, bypassing DNS-layer security controls.

---

## Recommendations for Detection Rule Tuning

Based on the timeline, the following detection opportunities exist:

| Detection Opportunity | Rule Logic | Timestamp Evidence |
|---|---|---|
| Anomalous User-Agent on workstation | Alert on `curl/*` or `wget/*` User-Agent from non-server internal IPs | `72.622252s` |
| PE file delivered with non-executable extension | Inspect file magic bytes at proxy/gateway; alert on `4D 5A` in `.pdf` responses | `72.891045s` |
| Internal host direct-IP HTTP communication | Alert on HTTP requests from workstations to external IPs without DNS resolution | `72.622252s` / `373.903849s` |
| HTTP POST from workstation to external IP | Alert on outbound POST requests from internal workstations over standard HTTP port | `373.903849s` |

---

*Timeline reconstructed by Gbemisola Faith Akinlabi | SOC Analyst*
*Source: Wireshark PCAP Analysis — Incident INC-2024-0019*
