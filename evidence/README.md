# Evidence — PCAP Capture File

This folder contains the raw network capture file used as the primary evidence source for this SOC investigation.

---

## File

| Field | Details |
|---|---|
| **Filename** | `trickbot-infection-traffic.pcap` |
| **Size** | 15 MB |
| **Format** | Wireshark PCAP — version 2.4, microsecond timestamps, Ethernet |
| **Capture Length** | 65,535 bytes |
| **Source** | Controlled academic environment — University of South Wales, MSc Applied Cyber Security |

---

## How to Use This File

Open the PCAP in Wireshark and follow the analysis workflow documented in [`queries/wireshark-filters.md`](../queries/wireshark-filters.md).

Suggested filter sequence to reproduce the full investigation:

```
# Step 1 — Identify suspicious HTTP download
http

# Step 2 — Confirm infected host IP
http.request

# Step 3 — Recover hostname
bootp

# Step 4 — Confirm hostname via SMB
smb

# Step 5 — Recover MAC address
arp

# Step 6 — Recover user account
kerberos.CNameString

# Step 7 — Verify PE signature in the transferred file
frame contains "MZ"

# Step 8 — Isolate C2 communication
ip.src == 10.8.19.101 && ip.dst == 103.148.41.195

# Step 9 — Reconstruct C2 session
tcp.stream eq X   (apply to the POST packet above)

# Step 10 — Confirm absence of DNS resolution to attacker IPs
dns
```

---

## Key Traffic Events in This Capture

| Timestamp (s) | Event |
|---|---|
| 0.000000 | DHCP Request — host `DESKTOP-M1TFHB6` broadcasts for IP lease |
| 0.000124 | DHCP ACK — IP `10.8.19.101` assigned |
| 72.622252 | HTTP GET — `ooiwy.pdf` downloaded from `185.244.41.29` via `curl/7.55.1` |
| 72.891045 | HTTP Response — TrickBot DLL payload served (MZ header: `4D 5A`) |
| 95.429052 | Further outbound HTTP — continued communication with delivery server |
| 373.903849 | HTTP POST — C2 beacon transmitted to `103.148.41.195` |
| 374.218763 | Victim system data exfiltrated in POST body |

---

## ⚠️ Disclaimer

This PCAP file was captured in a controlled academic lab environment as part of coursework for the MSc Applied Cyber Security programme at the University of South Wales. It is published here for **educational and cybersecurity research purposes only**.

- Do not execute any files extracted from this PCAP outside of an isolated sandbox environment
- The malicious IP addresses documented in this capture are published solely as indicators of compromise
- No live systems were compromised in the creation of this capture
