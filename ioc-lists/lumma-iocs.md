# IOC List: Lumma Stealer — 2026-01-31
## Author: Lalith Vardhan Boddala

---

## Network IOCs

| IOC | Type | Confidence | Action |
|---|---|---|---|
| whitepepper.su | C2 Domain | Critical | Block at DNS + Firewall |
| 172.56.88.98 | Secondary C2 IP | High | Block at Firewall |
| /api/set_agent | C2 URI Path | High | Alert on web proxy |
| act=log | C2 Parameter | High | Alert on web proxy |
| port 80 outbound | C2 Port | Medium | Monitor + alert |

## Host IOCs

| IOC | Type | Confidence |
|---|---|---|
| 3BF67EC05320C5729578BE4C0ADF174C | Bot/Agent ID | High |
| 842e2802df0f0a06b4ed51f12f4387e761523b | Auth Token | High |
| 54ce0109-19b4-4b2a-9869-ad2fdcaf34cb.local | Victim hostname | High |
| 10.1.21.58 | Victim internal IP | High |
| nginx/1.29.1 | C2 Server fingerprint | Medium |

## Behavioural IOCs

| Behaviour | Significance | MITRE |
|---|---|---|
| Large HTTP POST to .su domain | Data exfiltration | T1041 |
| JavaScript browser fingerprinting | System discovery | T1082 |
| LSARPC + DCE/RPC calls | Credential dumping | T1003.001 |
| WebDriver detection in JS | Sandbox evasion | T1497 |
| Two-stage payload delivery | Defense evasion | T1105 |
| Chrome User-Agent masquerade | Masquerading | T1036 |

---

*Lalith Vardhan Boddala | SOC Home Lab Portfolio*
