# hopscan
Email analysis tool written in Python. Scan **.eml** and **.txt** files for header analysis, security scoring, and verdict report.

<img width="500" height="500" alt="hopscanlogo2" src="https://github.com/user-attachments/assets/c40b8f15-3609-451c-8647-145762cba07e" />

---
### Current Features
**1. Extraction**:
- Headers
- Domains
- Authentication flags
- Timestamps
- IP addresses
- Geolocation data (*MaxMind DB 2025*)
- ASN data (*MaxMind DB 2025*)

**2. Severity score calculation**:
- Time travel (Large penalty)
- SPF/DKIM/DMARC (Pass, Fail, or None)
- Private hops count (Small penalty)

**3. Output:**
- Analysis results, verdict, and description.
- All domains extracted.
- CLI; Uses *Colorama* for legibility and color-coding.
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
### Disclaimer
**hopscan** is a personal and educational project created to explore Python programming and concepts in email header analysis, fraud detection, and cybersecurity research.
This software is provided “**as is**”, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement.

The author makes **no guarantees** regarding the accuracy, reliability, or completeness of the results produced by this program. Users are solely responsible for how they interpret or act upon the information generated. **HopScan should not be relied upon as a definitive or automated security solution.**

By using this software, you agree that the author shall **not be held liable** for any damages, losses, or consequences arising from the use or misuse of the program, its outputs, or its data sources.

**For educational and research purposes only. Do not use this tool for unlawful or unethical activities.**
