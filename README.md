# hopscan™
Email analysis tool written in Python. Scan **.eml** and **.txt** files for header analysis, security scoring, and verdict report.

<img width="1000" height="562" alt="hopscanlogo3" src="https://github.com/user-attachments/assets/1ee8b3a0-5080-4bc2-bbeb-e829fdde789b" />

<sub>*hopscan™ logo © 2025 Dante Coleman. All rights reserved.*</sub>

---
### Current Features
**1. Extraction**:
- Headers
<img width="506" height="240" alt="headers" src="https://github.com/user-attachments/assets/6ee30578-da7f-46eb-a370-968c51f75a2a" />

- Domains
- Authentication flags
- Timestamps
- IP addresses
<img width="538" height="381" alt="hops" src="https://github.com/user-attachments/assets/43490f9a-ac79-4493-a8a9-18fed1abf95f" />

- Geolocation data (*MaxMind DB 2025*)
- ASN data (*MaxMind DB 2025*)

**2. Severity score calculation**:
- Time travel (Large penalty)
- SPF/DKIM/DMARC (Pass, Fail, or None)
- Private hops count (Small penalty)
<img width="559" height="128" alt="analysis" src="https://github.com/user-attachments/assets/0ed475d4-9f7e-479d-9e2e-95f3322f44cc" />

**3. Output:**
- Analysis results, verdict, and description.
- All domains extracted.
- CLI; Uses *Colorama* for legibility and color-coding.
<img width="485" height="55" alt="verdict" src="https://github.com/user-attachments/assets/cb87e8a6-6baa-4c0f-a235-6b6021988cec" />

---
### Usage
1. Install Python.
> [!NOTE]
> Latest version recommended. Homebrew recommended for macOS.
3. Open a terminal in the [hopscan]() directory.
4. Create a Python venv and activate it.
> [!NOTE]
> Using a virtual environment is highly recommended.
6. Install pip requirements from [requirements.txt](requirements.txt):
   ```
   pip install -r requirements.txt
   ```
7. Run hopscan:
   ```
   python hopscan.py "Path:\To\Email-File.eml"
   ```
   or
   ```
   python hopscan.py folder_in_hopscan_directory/Email-File.eml
   ```
---
### To-Do List
**<ins>In-Progress</ins>:**
- Finish/Improve geolocation and ASN analysis.

**Detections:**
- Add detection: Timezone mismatch.
- Add detection: Authentication passes for a relay but fails for origin.
- Add detection: Spam and reputation headers from Microsoft, Google, etc.

**Verifications:**
- Add verification: HELO hostnames.
- Add verification: AbuseIPDB, VirusTotal, and WhoIS DNS.

**Analysis:**
- Add analysis: High-risk domain protection via listing, fuzzy matching, and strict thresholds.
- Add analysis: Base64, obfuscation, entropy in headers and bodies.
- Add analysis: Keywords and linguistics (Fraud, urgency, obfuscation).
- Add analysis: URLs and attachments.

**Features:**
- Add feature: Export to CSV and JSON.
- Add feature: Verbose reporting option.
- Add feature: Sensitivity adjustment option.
- Add feature: Caching for large data volumes.
- Add feature: GUI.
---
### License
All rights reserved.

This repository and its contents are the intellectual property of Dante Coleman.
No part of this codebase may be copied, modified, or redistributed without explicit permission.

This project uses GeoLite2 data created by MaxMind, available from https://www.maxmind.com.
Each database folder within the /databases directory contains its own license provided by MaxMind and is governed by the MaxMind End User License Agreement.

---
### Attribution
This project uses GeoLite2 data created by [MaxMind](https://www.maxmind.com).

---
### Disclaimer
**hopscan™** is a personal and educational project created to explore Python programming and concepts in email header analysis, fraud detection, and cybersecurity research.
This software is provided “**as is**”, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement.

The author makes **no guarantees** regarding the accuracy, reliability, or completeness of the results produced by this program. Users are solely responsible for how they interpret or act upon the information generated. **hopscan™ should not be relied upon as a definitive or automated security solution.**

By using this software, you agree that the author shall **not be held liable** for any damages, losses, or consequences arising from the use or misuse of the program, its outputs, or its data sources.

**For educational and research purposes only. Do not use this tool for unlawful or unethical activities.**
