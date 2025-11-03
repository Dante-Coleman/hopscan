![Python](https://img.shields.io/badge/python-3.13.7-blue)
![Dependencies](https://img.shields.io/badge/dependencies-2-brightgreen)
![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red)
# hopscan™
Email analysis tool written in Python. Scan **.eml** and **.txt** files for header analysis, security scoring, and verdict report.

**hopscan™** helps cybersecurity enthusiasts and analysts quickly assess email threats by analyzing headers, authentication, and domain reputation.

This project is also a personal learning journey in Python, email forensics, and cybersecurity analysis.

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
- CLI tool; uses *Colorama* for color-coded output.
<img width="485" height="55" alt="verdict" src="https://github.com/user-attachments/assets/cb87e8a6-6baa-4c0f-a235-6b6021988cec" />

---
### Usage
1. Install Python.
> [!NOTE]
> Latest version recommended. Homebrew recommended for macOS.
2. Open a terminal in the [hopscan](./) directory.
3. Create a Python virtual environment and activate it:
```
python -m venv venv        # Create venv
source venv/bin/activate    # Unix/macOS
venv\Scripts\activate       # Windows
```
> [!NOTE]
> Using a virtual environment is highly recommended.
4. Install pip requirements from [requirements.txt](requirements.txt):
   ```
   pip install -r requirements.txt
   ```
5. Run hopscan:
   ```
   python hopscan.py "Path:\To\Email-File.eml"
   ```
   or
   ```
   python hopscan.py folder_in_hopscan_directory/Email-File.eml
   ```
---
### Dependencies
This project requires Python 3.13+ and the following packages (install via `pip install -r requirements.txt`):

- [Colorama](https://pypi.org/project/colorama/) – for colored CLI output
- [geoip2](https://pypi.org/project/geoip2/) – for MaxMind geolocation queries

---
### Future Improvements
- Geolocation and ASN analysis refinement.
- Additional detection rules (timezone mismatch, relay vs. origin authentication).
- External verifications (HELO hostnames, AbuseIPDB, VirusTotal, WhoIS).
- Advanced analysis (base64/obfuscation detection, high-risk domain matching, URL & attachment scanning).
- Export options (CSV/JSON), verbose reporting, sensitivity adjustment, caching, and GUI.

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
