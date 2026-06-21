# 🔬 Network Traffic Analysis — Malware PCAP Investigation

> **Real-world malware traffic analysis** using Wireshark on authentic malicious PCAPs — Lumma Stealer C2 communication decoded, browser fingerprinting exfiltration captured, and DNS-based infection patterns identified. All findings mapped to MITRE ATT&CK.

---

## 📋 Overview

Analysis of two real malicious network captures from
[malware-traffic-analysis.net](https://malware-traffic-analysis.net) —
a resource used by professional SOC analysts and threat intelligence teams.

**Built by:** Lalith Vardhan Boddala  
**Purpose:** SOC Analyst L1 portfolio — GitHub / LinkedIn  
**Focus:** Network forensics, malware C2 analysis, IOC extraction, Wireshark

---

## 🦠 PCAPs Analysed

| PCAP | Malware | Key Finding |
|---|---|---|
| 2026-01-31 | Lumma Stealer | C2 at whitepepper.su — 15,998 bytes of victim data exfiltrated |
| 2025-01-22 | Fake Software Site | DNS-only capture — internal network topology exposed |

---

## 🔍 Key Findings

### PCAP 1 — Lumma Stealer (2026-01-31)

**C2 Infrastructure Identified:**
```
Primary C2:   whitepepper.su (HTTP port 80)
Secondary C2: 172.56.88.98 (payload delivery — failed)
Bot ID:       3BF67EC05320C5729578BE4C0ADF174C
API Endpoint: /api/set_agent?id=...&token=...&act=log
C2 Server:    nginx/1.29.1
```

**Data Exfiltrated (confirmed in Wireshark HTTP stream):**
- Windows 10 x64, Chrome 144, AMD Radeon R9 200 GPU
- Screen resolution 1920x1080, 12 CPU cores
- Canvas fingerprint (unique device identifier)
- Installed fonts, audio context, WebRTC config
- Browser plugins, network connection quality
- **Total: 15,998 bytes across 2 POST requests**

**Additional Activity:**
- DCE/RPC + LSARPC traffic — credential dumping attempt (T1003.001)
- WebDriver detection in C2 JavaScript — sandbox evasion (T1497)
- Two-stage delivery architecture — fingerprint then payload

---

### PCAP 2 — Fake Software Site (2025-01-22)

**Network Topology Exposed:**
```
Internal Domain: bluemoontuesday.com
DNS Server:      win-gsh54qlw48d (MAC: 00:24:e8:7f:09:5d)
Victim Machine:  DESKTOP-L8C5GSJ (MAC: 00:d0:b7:26:4a:74)
```

**Key Analytical Finding:**
DNS-only traffic in this capture is not a clean bill of health —
it reflects a limited capture scope at the DNS server level.
The actual malware C2 (likely HTTPS) occurred on a different
network segment. This demonstrates why SOC analysts must
understand network position when interpreting PCAPs.

---

## 🛠️ Wireshark Filters Used

```wireshark
# C2 traffic identification
http.host == "whitepepper.su"

# Data exfiltration — POST requests
http.request.method == "POST"

# DNS analysis
dns
dns.flags.response == 1
dns.a

# Internal network topology
nbns

# Credential access
dcerpc
lsarpc

# Secondary C2
ip.addr == 172.56.88.98

# Pre-infection traffic
frame.number < 24500 && http

# External connections
ip.dst != 10.1.21.58 && ip.dst != 10.1.21.1
```

---

## 🗺️ MITRE ATT&CK Coverage

### Lumma Stealer
| Technique | ID | Evidence |
|---|---|---|
| Drive-by Compromise | T1189 | Initial HTTP infection |
| Ingress Tool Transfer | T1105 | Secondary payload attempt |
| System Information Discovery | T1082 | OS/hardware exfiltrated |
| Browser Information Discovery | T1217 | Chrome plugins enumerated |
| OS Credential Dumping: LSASS | T1003.001 | LSARPC traffic |
| Exfiltration Over HTTP | T1041 | 15,998 bytes to whitepepper.su |
| Masquerading | T1036 | Chrome User-Agent used |
| Virtualization/Sandbox Evasion | T1497 | WebDriver detection |

### Fake Software Site
| Technique | ID | Evidence |
|---|---|---|
| DNS C2 | T1071.004 | DNS-only traffic pattern |
| Dynamic Resolution | T1568 | Dynamic DNS updates |
| Non-Application Layer Protocol | T1095 | ICMP port unreachable |

---

## 📁 Repository Structure

```
network-traffic-analysis/
├── README.md
├── analysis/
│   ├── lumma-stealer-analysis.md      ← full C2 + exfil analysis
│   └── fake-software-site-analysis.md ← DNS pattern + topology
├── ioc-lists/
│   ├── lumma-iocs.md                  ← C2 IPs, domains, tokens
│   └── fake-software-iocs.md          ← hostnames, MACs, behaviours
└── screenshots/
    ├── wireshark-protocol-hierarchy-lumma.png
    ├── wireshark-http-objects-lumma.png
    ├── wireshark-c2-traffic-whitepepper.png
    ├── wireshark-http-stream-exfiltration.png
    ├── wireshark-conversations-lumma.png
    ├── wireshark-dns-2025.png
    └── wireshark-dns-responses-2025.png
```

---

## 🎯 Skills Demonstrated

`Wireshark` `PCAP Analysis` `Malware Traffic Analysis`
`C2 Detection` `IOC Extraction` `HTTP Stream Analysis`
`DNS Forensics` `Browser Fingerprinting` `MITRE ATT&CK`
`Network Forensics` `Threat Intelligence` `Lumma Stealer`
`Protocol Analysis` `Credential Access Detection`

---

## 🔗 Related Projects

- [Splunk SIEM Home Lab](https://github.com/lalithvardhan434/splunk-siem-homelab) — Project 1
- [Phishing Incident Response](https://github.com/lalithvardhan434/phishing-incident-response) — Project 2

---

*Lalith Vardhan Boddala | SOC Home Lab Portfolio*  
*PCAPs sourced from: malware-traffic-analysis.net (Brad Duncan)*
