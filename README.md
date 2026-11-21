![GitHub release](https://img.shields.io/github/v/release/Dante-Coleman/hopscan)
![Python](https://img.shields.io/badge/python-3.13+-blue)
![Dependencies](https://img.shields.io/badge/dependencies-2-brightgreen)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
# hopscan
Email analysis tool written in Python. Scan **.eml** and **.txt** files for header analysis, security scoring, and verdict report.

**hopscan** helps cybersecurity enthusiasts and analysts quickly assess email threats by analyzing headers, authentication, and domain reputation.

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
- IP addresses (IPv4 and IPv6, with private/reserved ranges separated out)
<img width="879" height="499" alt="hops" src="https://github.com/user-attachments/assets/18f8cc0b-3b5b-48b3-b24c-414fab341f4d" />


- Geolocation data (*MaxMind DB 2025*)
- ASN data (*MaxMind DB 2025*)

**2. Severity score calculation**:
Every point added or taken away is listed under **FINDINGS** in the report, so you can see why a verdict was reached.

| Signal | Points |
|---|---|
| No trusted Authentication-Results header | −10 |
| SPF pass / softfail / fail / none or error | +5 / −5 / −15 / −3 |
| DKIM pass *aligned with the From domain* / fail / none | +5 / −15 / −3 |
| DMARC pass / fail / none or error | +10 / −30 / −5 |
| Display name contains a different domain's address (`"support@paypal.com" <x@evil.example>`) | −25 |
| Reply-To domain differs from From | −10 |
| Return-Path domain differs from From (only when DMARC didn't pass) | −5 |
| Received timestamps go backwards by more than 5 minutes | −10 |

Only the **topmost** Authentication-Results header is trusted by default, because it is the one your mail server added. Any header below it could have been written by the sender. Use `--trusted-authserv` to name your provider's server instead.

ASN categories (major provider, hosting, ISP/VPS) are shown for context but don't affect the score, since phishing is often sent through large, reputable providers.
<img width="430" height="123" alt="analysis" src="https://github.com/user-attachments/assets/524a60dd-8a87-4b30-acc3-6652625910c9" />


**3. Output:**
- Analysis results, verdict, and description.
- All domains extracted.
- CLI tool; uses *Colorama* for color-coded output.
- `--json` for machine-readable output.
<img width="496" height="52" alt="verdict" src="https://github.com/user-attachments/assets/fa8cf11a-13d6-4ffb-b6ca-371f9de9fbb7" />


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

**Options**
| Option | What it does |
|---|---|
| `--json` | Print results as JSON instead of the colored report |
| `--trusted-authserv ID` | Only trust Authentication-Results headers from this server (e.g. `mx.google.com`). Repeatable. |
| `--db-dir PATH` | Folder containing the GeoLite2 databases (also settable with `HOPSCAN_DB_DIR`) |
| `--no-geo` | Skip GeoIP/ASN lookups |

**Updating the GeoLite2 databases:** download the newest City and ASN databases from MaxMind and put their folders in [/databases](/databases). hopscan picks the newest `GeoLite2-City*` and `GeoLite2-ASN*` folders automatically. MaxMind's license asks that the data be kept up to date.

**Running the tests**
```
pip install pytest
python -m pytest
```
---
### Dependencies
This project is tested on Python 3.13 and the following packages (install via `pip install -r requirements.txt`):

- [Colorama](https://pypi.org/project/colorama/) – for colored CLI output
- [geoip2](https://pypi.org/project/geoip2/) – for MaxMind geolocation queries

---
### Future Improvements
- Geolocation and ASN analysis refinement.
- Additional detection rules (timezone mismatch, lookalike domains, brand impersonation).
- Use the Public Suffix List for domain alignment (currently approximated).
- External verifications (HELO hostnames, AbuseIPDB, VirusTotal, WhoIS).
- Advanced analysis (base64/obfuscation detection, high-risk domain matching, URL & attachment scanning).
- Export options (CSV/JSON), verbose reporting, sensitivity adjustment, caching, and GUI.

---
### License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

### Logo Usage
The hopscan™ logo is © 2025 Dante Coleman. All rights reserved. The logo is not covered by the MIT License and may not be used without permission.

---

### Third-Party Data
This project uses GeoLite2 data created by [MaxMind](https://www.maxmind.com), available from https://www.maxmind.com. Each database folder within the [/databases](/databases) directory contains its own license provided by MaxMind.

---
### Disclaimer
**hopscan** is a personal and educational project created to explore Python programming and concepts in email header analysis, fraud detection, and cybersecurity research.
This software is provided “**as is**”, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement.

The author makes **no guarantees** regarding the accuracy, reliability, or completeness of the results produced by this program. Users are solely responsible for how they interpret or act upon the information generated. **hopscan should not be relied upon as a definitive or automated security solution.**

By using this software, you agree that the author shall **not be held liable** for any damages, losses, or consequences arising from the use or misuse of the program, its outputs, or its data sources.

**For educational and research purposes only. Do not use this tool for unlawful or unethical activities.**
