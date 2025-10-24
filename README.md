# 🛡️ PacketSentinel - Network Forensics & Threat Hunting

**Advanced PCAP Analysis for SOC Operations | Lokibot Infostealer Investigation**

![Project Status](https://img.shields.io/badge/Status-Complete-success)
![Malware Family](https://img.shields.io/badge/Malware-Lokibot-red)
![Detection Rules](https://img.shields.io/badge/Detection%20Rules-13-orange)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-9%20Techniques-purple)
![Analysis Tool](https://img.shields.io/badge/Tool-Tshark%20%7C%20Wireshark-blue)

---

## 📊 Project Overview

Comprehensive network forensic analysis of a real-world Lokibot infostealer trojan infection, demonstrating production-grade SOC analyst capabilities through:

- **PCAP Triage & Protocol Analysis** - Tshark-based packet inspection
- **IOC Extraction & Correlation** - Automated indicator collection with VirusTotal API
- **Behavioral Analysis** - C2 beaconing pattern identification (60-second intervals)
- **Malware Binary Extraction** - Carved and validated against 63 AV vendors
- **Detection Engineering** - 13 production-ready signatures (Suricata, Sigma, YARA)
- **MITRE ATT&CK Mapping** - 9 techniques across 6 tactics

**Analysis Date:** October 2025  
**PCAP Source:** [Malware-Traffic-Analysis.net](https://malware-traffic-analysis.net)  
**Infection Date:** October 12, 2020  
**Analyst:** Phiwokuhle Sdingo Kunene

---

## 🎯 Key Findings

### Infection Summary

| Metric | Value | Significance |
|--------|-------|--------------|
| **Victim IP** | 10.10.12.101 | Internal Windows 10 host |
| **Malware Family** | Lokibot Infostealer | Keylogger + screenshot stealer |
| **C2 Beaconing** | Every 60 seconds | Clockwork precision (automated) |
| **Data Exfiltrated** | 1.3 MB | Keylog data + screenshots |
| **Detection Rate** | 63/70+ vendors (90%) | High-confidence malware |

### Malicious Infrastructure

**Download Domain:**
- `millsmiltinon.com` - **13/90 VT detections** (malware distribution)

**C2 Servers:**
- `104.223.143.132` (AWS-hosted) - **10/63 VT detections** (Primary C2)
- `45.14.112.133` (UK hosting) - **0/61 VT detections** (False negative - proven malicious via behavioral analysis)

**Malware Binary:**
- **Filename:** Xehmigm.exe
- **SHA256:** `6b53ba14172f0094a00edfef96887aab01e8b1c49bdc6b1f34d7f2e32f88d172`
- **Size:** 629,760 bytes (615 KB)
- **Type:** PE32 executable (Win32 EXE)

### Attack Timeline
```
17:02:18 EDT - User downloads Xehmigm.exe from millsmiltinon.com
              ↓
17:02:53 EDT - Malware executes (User-Agent "PPPPPX" appears)
              ↓
17:02:58 EDT - 3 rapid POST requests to 104.223.143.132/ecflix/Panel/five/fre.php
              ↓
17:03:59 EDT - Regular 60-second beaconing begins
              ↓
  Ongoing    - 1.3 MB data exfiltrated to 45.14.112.133
```

---

## 🔍 Technical Analysis Highlights

### C2 Beaconing Pattern (Signature Behavior)

**Characteristic:** Exactly 60-second intervals - Machine-like precision
```
Time        | Action
17:02:58    | Initial check-in (3 rapid beacons)
17:03:59    | Beacon (+61 seconds)
17:05:00    | Beacon (+61 seconds)
17:06:00    | Beacon (+60 seconds)
...         | Continues with clockwork regularity
```

**C2 Details:**
- **Server:** 104.223.143.132 (Amazon AWS)
- **URI:** `/ecflix/Panel/five/fre.php`
- **Method:** HTTP POST (unencrypted)
- **User-Agent:** "PPPPPX" (unique Lokibot fingerprint)
- **Response Size:** 23 bytes (minimal acknowledgment)

### Unique IOCs Discovered

**Network Indicators:**
```
- User-Agent: PPPPPX (100% unique to Lokibot)
- User-Agent: Mozilla/4.08 (Charon; Inferno)
- C2 Panel Path: /ecflix/Panel/five/fre.php
- Beacon Interval: 60 seconds ±1 second
```

**File Indicators:**
```
- Xehmigm.exe - SHA256: 6b53ba14172f0094a00edfef96887aab01e8b1c49bdc6b1f34d7f2e32f88d172
- Xehmuth - SHA256: b1fd9868dc4dd1a07baed3572143e945ca66fea3f542bbf8d98c9b96032542f9
```

---

## 🛠️ Methodology & Tools

### Analysis Workflow
```
1. PCAP Triage
   └─ tshark conversation analysis
   └─ Protocol hierarchy statistics
   
2. IOC Extraction
   └─ HTTP requests/responses
   └─ DNS queries
   └─ File carving
   
3. Threat Intelligence
   └─ VirusTotal API (IP/domain/file reputation)
   └─ AbuseIPDB (IP abuse scoring)
   └─ AlienVault OTX (community intel)
   
4. Behavioral Analysis
   └─ Beacon interval calculation
   └─ Data volume analysis
   └─ Timeline reconstruction
   
5. Detection Engineering
   └─ Suricata IDS signatures
   └─ Sigma SIEM rules
   └─ YARA pattern matching
   
6. MITRE ATT&CK Mapping
   └─ Technique identification
   └─ Tactic coverage analysis
```

### Tools Used

| Tool | Purpose | Key Feature |
|------|---------|-------------|
| **Tshark** | CLI packet analysis | Automated IOC extraction |
| **Wireshark** | Visual traffic inspection | Protocol deep-dive |
| **VirusTotal API** | Threat intelligence | Multi-vendor reputation |
| **Python** | Automation scripting | API integration |
| **Suricata** | Network IDS | Real-time detection |
| **Sigma** | SIEM rule framework | Platform-agnostic queries |
| **YARA** | Pattern matching | File/traffic signatures |


## 🎯 Detection Rules (13 Total)

### Suricata IDS Signatures (8 Rules)
```
1. Lokibot C2 Beacon to Known Panel (sid:8000001)
2. Unique User-Agent "PPPPPX" Detection (sid:8000002)
3. Malware Download from millsmiltinon.com (sid:8000003)
4. Regular 60-Second Beaconing Pattern (sid:8000004)
5. Secondary C2 Server Communication (sid:8000005)
6. Suspicious "Charon; Inferno" User-Agent (sid:8000006)
7. Known Malware Hash in Transit (sid:8000007)
8. POST to Suspicious PHP Panel Path (sid:8000008)
```

**Deployment:**
```bash
suricata -c /etc/suricata/suricata.yaml \
  -S IOCs/suricata/lokibot_signatures.rules \
  -i eth0
```

### Sigma SIEM Rule (1 Rule)

**Rule:** Lokibot 60-Second C2 Beaconing Pattern  
**Logic:** Triggers on 8+ connections to malicious IPs in 10 minutes  
**Level:** CRITICAL

**Splunk Query:**
```spl
index=firewall dest_ip IN (104.223.143.132, 45.14.112.133) dest_port=80
| stats count by src_ip
| where count > 8
```

### YARA Patterns (4 Rules)
```
1. Lokibot_C2_Traffic_Pattern - Detects /ecflix/Panel/five/fre.php + PPPPPX
2. Lokibot_Download_URL_Pattern - Identifies millsmiltinon.com downloads
3. Lokibot_Binary_In_Memory - PE analysis for malware artifacts
4. Lokibot_Beacon_Data_Pattern - C2 traffic characteristics
```

**Usage:**
```bash
yara IOCs/yara/lokibot_traffic.yar captured_traffic.pcap
```

---

## 🗺️ MITRE ATT&CK Coverage

### Techniques Mapped (9 Total)

| Tactic | Technique | Evidence | Confidence |
|--------|-----------|----------|------------|
| **Initial Access** | T1566.001 (Phishing Attachment) | Malicious .exe download | HIGH |
| **Execution** | T1204.002 (User Execution) | User ran Xehmigm.exe | HIGH |
| **Command & Control** | T1071.001 (Web Protocols) | HTTP POST beaconing | CONFIRMED |
| **Collection** | T1056.001 (Keylogging) | Lokibot capability | HIGH |
| **Collection** | T1113 (Screen Capture) | 1.3 MB exfiltration | MEDIUM |
| **Exfiltration** | T1041 (C2 Channel) | Data via POST | CONFIRMED |
| **Exfiltration** | T1567.001 (Web Service) | Discord DNS query | MEDIUM |
| **Defense Evasion** | T1027 (Obfuscation) | Randomized URL path | MEDIUM |
| **Persistence** | T1547.001 (Registry Run Keys) | Typical Lokibot behavior | LOW |


## 🎓 Skills Demonstrated

### Technical Capabilities

✅ **Network Forensics**
- PCAP analysis (Tshark, Wireshark)
- Protocol decoding (HTTP, DNS, TCP)
- Packet filtering and IOC extraction
- Traffic pattern recognition

✅ **Threat Intelligence**
- VirusTotal API integration
- Multi-source indicator correlation
- False positive/negative analysis
- Infrastructure attribution

✅ **Detection Engineering**
- Suricata IDS signature development
- Sigma SIEM rule creation
- YARA pattern matching
- Behavioral anomaly detection

✅ **Malware Analysis**
- File carving from network traffic
- Binary hash validation
- Behavioral analysis (C2 beaconing)
- Timeline reconstruction

✅ **Automation & Scripting**
- Python automation (API calls, data parsing)
- Bash scripting (batch processing)
- JSON/CSV data manipulation

### Operational Skills

✅ **Incident Response**
- Attack chain reconstruction
- IOC extraction and documentation
- Threat prioritization
- Remediation recommendations

✅ **MITRE ATT&CK Framework**
- Technique identification
- Tactic mapping
- Defensive gap analysis
- Coverage assessment

✅ **Technical Communication**
- Executive summary writing
- Technical report documentation
- Visual timeline creation
- Finding presentation

---

## 📈 Project Metrics

| Metric | Value |
|--------|-------|
| **PCAP Size** | 1.3 MB / 1,546 packets |
| **Analysis Duration** | 693 seconds captured (~11.5 minutes) |
| **IOCs Extracted** | 3 IPs, 1 domain, 2 file hashes |
| **Malware Detection** | 63/70+ vendors (90% rate) |
| **Detection Signatures** | 13 (8 Suricata + 1 Sigma + 4 YARA) |
| **MITRE Coverage** | 9 techniques, 6 tactics |
| **Threat Intel Sources** | 3 (VirusTotal, AbuseIPDB, AlienVault OTX) |
| **Reports Generated** | 10+ technical documents |

---

## 💼 Use Cases

### For SOC Analysts
- Learn PCAP analysis workflow
- Understand C2 beaconing patterns
- Practice IOC extraction techniques
- Study malware behavioral analysis

### For Threat Hunters
- Behavioral detection methodology
- Correlation across threat intel sources
- Pattern recognition in network traffic
- Proactive hunting queries

### For Detection Engineers
- Production-ready signature examples
- Multi-platform rule development (Suricata, Sigma, YARA)
- Behavioral vs signature-based detection
- Rule tuning and validation

### For Incident Responders
- Attack timeline reconstruction
- Evidence collection and preservation
- IOC documentation standards
- Reporting and communication templates

---

## 📚 References & Resources

### Malware Intelligence
- [Malware-Traffic-Analysis.net](https://malware-traffic-analysis.net) - PCAP source
- [MalwareBazaar](https://bazaar.abuse.ch/) - Malware sample repository
- [Malpedia - Lokibot](https://malpedia.caad.fkie.fraunhofer.de/details/win.lokibot)

### Detection Frameworks
- [Suricata Documentation](https://suricata.readthedocs.io/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [YARA Documentation](https://yara.readthedocs.io/)

### Threat Intelligence
- [VirusTotal](https://www.virustotal.com)
- [AbuseIPDB](https://www.abuseipdb.com)
- [AlienVault OTX](https://otx.alienvault.com)

### Frameworks
- [MITRE ATT&CK](https://attack.mitre.org)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

---

## 🤝 Contributing

This project demonstrates security analysis capabilities. However, if you find issues with detection rules or have suggestions for improvements:

1. Open an issue describing the problem/enhancement
2. For rule improvements, include test cases
3. Ensure any PRs maintain documentation quality

---

## ⚖️ Legal & Ethical Considerations

### Disclaimer

**Educational Purpose Only:** This project analyzes real malware samples for defensive security research and education. All analysis conducted in isolated lab environment (REMnux VM).

**Do Not:**
- Execute malware samples outside controlled environments
- Use detection rules to facilitate malicious activity
- Distribute malware binaries
- Perform analysis on networks without authorization

**Responsible Disclosure:** All IOCs are from publicly available sources (Malware-Traffic-Analysis.net) and are shared for defensive purposes only.

### Data Sources

- **PCAP:** Public malware traffic capture from Malware-Traffic-Analysis.net
- **Malware Sample:** Lokibot infostealer (publicly documented threat)
- **Victim IP:** 10.10.12.101 is from sample PCAP, not a real network

---

## 📧 Contact

**Analyst:** Phiwokuhle Sdingo Kunene  
**Project:** PacketSentinel - Network Forensics & Threat Hunting  
**LinkedIn:** https://www.linkedin.com/in/phiwokuhlesdingo/   

---

## 📜 License

MIT License

Copyright (c) 2025 Phiwokuhle Sdingo Kunene

Permission is hereby granted, free of charge, to any person obtaining a copy of detection signatures and analysis documentation in this repository for use in production security monitoring systems with attribution.

**Detection Rules:** Free for production use with attribution  
**Documentation:** Available under Creative Commons BY 4.0

---

## 🌟 Acknowledgments

- **Malware-Traffic-Analysis.net** - For providing high-quality malware traffic samples
- **Brad Duncan** - For maintaining Malware-Traffic-Analysis.net
- **VirusTotal** - For threat intelligence API access
- **REMnux Team** - For the excellent malware analysis toolkit

---

**⭐ If this project helped you learn network forensics, consider starring the repository!**

---

