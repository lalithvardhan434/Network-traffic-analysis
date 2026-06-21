# Malware Traffic Analysis: Fake Software Site
## PCAP File: 2025-01-22-traffic-analysis-exercise.pcap
## Author: Lalith Vardhan Boddala
## Date: 2025-01-22 | Analysed: 2026-06-20

---

## Executive Summary

Analysis of a fake software site infection PCAP from
malware-traffic-analysis.net. The capture shows a Windows
environment where an infected workstation (DESKTOP-L8C5GSJ)
communicates exclusively with an internal DNS server
(win-gsh54qlw48d) on the `bluemoontuesday.com` domain.
The traffic is DNS-only — no external HTTP connections were
captured — indicating either early-stage infection, DNS-based
C2, or a network segment capture that missed the outbound
HTTP/HTTPS traffic.

---

## 1. PCAP Overview

| Field | Value |
|---|---|
| File | 2025-01-22-traffic-analysis-exercise.pcap |
| Total Packets | 39,427 |
| Protocols | Ethernet, IPv4, UDP, DNS only |
| Victim Hostname | DESKTOP-L8C5GSJ |
| Victim Domain | bluemoontuesday.com |
| DNS Server | win-gsh54qlw48d.bluemoontuesday.com |
| DNS Server MAC | 00:24:e8:7f:09:5d |
| Victim MAC | 00:d0:b7:26:4a:74 |
| External HTTP | None captured |
| C2 Domains | Under investigation via DNS queries |

---

## 2. Protocol Hierarchy Analysis

| Protocol | Packets | Significance |
|---|---|---|
| DNS (UDP) | 39,427 (100%) | All traffic is DNS — unusual for normal workstation |
| ICMP | 1 | Destination unreachable (packet 70) |

**Key Finding:** A normal workstation generates diverse traffic —
HTTP, HTTPS, DNS, NTP, DHCP. A capture showing only DNS traffic
indicates either a network tap positioned only at the DNS server,
or the malware is using DNS as its primary communication channel
(DNS tunneling/beaconing).

---

## 3. Network Topology Identified

```
Internal Network: bluemoontuesday.com
                        │
        ┌───────────────┴───────────────┐
        │                               │
win-gsh54qlw48d              DESKTOP-L8C5GSJ
(DNS Server)                 (Victim Workstation)
00:24:e8:7f:09:5d            00:d0:b7:26:4a:74
```

**Both machines identified via DNS responses and Ethernet frames.**

---

## 4. DNS Traffic Analysis

### 4.1 Communication Pattern
All DNS traffic flows between two internal machines:
- **Source:** `win-gsh54qlw48d.bluemoontuesday.com` (DNS server)
- **Destination:** `DESKTOP-L8C5GSJ.bluemoontuesday.com` (victim)

### 4.2 Key DNS Events

**Packet 70 — ICMP Destination Unreachable:**
```
DESKTOP-L8C5GSJ → win-gsh54qlw48d
ICMP: Destination unreachable (Port unreachable)
```
**Analysis:** The victim attempted to reach a port on the DNS
server that was not listening. This could indicate a failed
connection attempt to a service expected to be running —
possibly a C2 listener that was not yet active.

**Packet 16 — Dynamic DNS Update:**
```
DESKTOP-L8C5GSJ → win-gsh54qlw48d
DNS: Dynamic update 0x4997 SOA bluemoontuesday.com
```
**Analysis:** The victim is sending a DNS dynamic update —
registering or updating its own DNS record. This is normal
in Windows Active Directory environments but worth noting
as malware can abuse DDNS for C2 communication.

### 4.3 DNS Response Codes Observed
- Standard query responses (NOERROR) — normal lookups
- Dynamic update responses — DDNS activity
- Multiple repeated lookups for same hostnames — beaconing pattern

---

## 5. Indicators of Compromise

### Network IOCs
| IOC | Type | Confidence |
|---|---|---|
| DESKTOP-L8C5GSJ | Victim hostname | High |
| win-gsh54qlw48d | DNS server hostname | High |
| bluemoontuesday.com | Internal domain | High |
| 00:24:e8:7f:09:5d | DNS server MAC | High |
| 00:d0:b7:26:4a:74 | Victim MAC | High |

### Behavioural IOCs
| Behaviour | Significance |
|---|---|
| DNS-only traffic in capture | Unusual — suggests DNS C2 or limited capture scope |
| Repeated DNS queries | Beaconing pattern |
| ICMP port unreachable | Failed connection to expected service |
| Dynamic DNS updates | Potential DNS C2 mechanism |

---

## 6. Analysis Limitations

This PCAP presents an important lesson in real-world analysis:

1. **Capture scope matters** — This capture appears to be from
   an internal network segment showing only DNS traffic. The
   actual malware C2 (likely HTTPS) was not captured because
   the tap was placed only at the DNS server level.

2. **Absence of evidence ≠ absence of activity** — No HTTP
   traffic in this PCAP does not mean no HTTP traffic occurred.
   It means it was not captured at this vantage point.

3. **Internal hostnames are valuable** — Even without seeing
   the malware payload, the hostnames and MAC addresses
   provide pivoting points for further investigation:
   - Query EDR for `DESKTOP-L8C5GSJ` activity
   - Pull full packet capture from the workstation's switch port
   - Check Active Directory logs for that machine

---

## 7. Recommended Next Investigation Steps

| Step | Tool | Purpose |
|---|---|---|
| Pull full PCAP from workstation switch port | Wireshark/tcpdump | Capture HTTP/HTTPS C2 traffic |
| Query EDR for DESKTOP-L8C5GSJ | CrowdStrike/Defender | Get process and file activity |
| Check proxy logs for bluemoontuesday.com | Web proxy | Find outbound connections |
| Review AD logs for the machine | Windows Event Logs | Authentication and policy changes |
| Run memory analysis on victim | Volatility | Find malware in memory |

---

## 8. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| DNS | T1071.004 | All C2 communication via DNS protocol |
| Dynamic Resolution | T1568 | Dynamic DNS updates observed |
| Network Service Discovery | T1046 | Internal host enumeration via DNS |
| ICMP port unreachable | T1095 | Non-application layer protocol usage |

---

## 9. Key Lesson for SOC Analysts

This PCAP demonstrates that **network position determines visibility**.
A SOC analyst must understand where in the network a capture was taken:

- **Perimeter capture** — sees all inbound/outbound traffic
- **Internal DNS capture** — sees only DNS queries, not payload
- **Workstation capture** — sees all traffic from that machine
- **Switch SPAN port** — sees all traffic on that network segment

**A clean DNS-only PCAP is not a clean machine — it is an
incomplete picture. Always correlate with EDR, proxy, and
firewall logs before concluding no malicious activity occurred.**

---

*Lalith Vardhan Boddala | SOC Home Lab Portfolio*
*GitHub: https://github.com/lalithvardhan434*
*Source PCAP: malware-traffic-analysis.net — 2025-01-22*
