# IOC List: Fake Software Site — 2025-01-22
## Author: Lalith Vardhan Boddala

---

## Network IOCs

| IOC | Type | Confidence | Action |
|---|---|---|---|
| bluemoontuesday.com | Internal victim domain | High | Investigate |
| win-gsh54qlw48d.bluemoontuesday.com | DNS server hostname | High | Investigate |
| DESKTOP-L8C5GSJ.bluemoontuesday.com | Victim hostname | High | Isolate machine |
| 00:24:e8:7f:09:5d | DNS server MAC address | High | Identify device |
| 00:d0:b7:26:4a:74 | Victim MAC address | High | Isolate device |

## Behavioural IOCs

| Behaviour | Significance | MITRE |
|---|---|---|
| DNS-only traffic (no HTTP/HTTPS) | Incomplete capture / DNS C2 | T1071.004 |
| Repeated DNS queries | Beaconing pattern | T1071.004 |
| Dynamic DNS updates | DNS C2 mechanism | T1568 |
| ICMP port unreachable (packet 70) | Failed C2 connection attempt | T1095 |

## Investigation Pivots

| Pivot | Tool | Purpose |
|---|---|---|
| DESKTOP-L8C5GSJ | EDR query | Get full process activity |
| 00:d0:b7:26:4a:74 | Switch/DHCP logs | Confirm IP assignment |
| bluemoontuesday.com | Proxy logs | Find outbound connections |

---

*Lalith Vardhan Boddala | SOC Home Lab Portfolio*
