# 🐍 Python Project – LogInspector: A Lightweight Log Parser & Threat Analyzer

## Project Summary

`LogInspector` is a simple but powerful Python tool designed to parse, analyze, and flag suspicious patterns in Windows event logs or Linux syslogs. It helps junior analysts or system admins quickly identify common threat behaviors such as brute-force login attempts, privilege escalation indicators, or PowerShell abuse. This is ideal for demonstrating Python scripting skills in a blue-team security context.

---

## Project Goals

* Parse plain-text logs from `.evtx`, `.log`, or `.txt` files
* Detect key indicators of suspicious behavior (e.g., Event ID 4625 or PowerShell with `-enc`)
* Highlight findings in terminal and save to an output file
* Learn basic regex and file handling for log analysis

---

## Skills Demonstrated

* Python scripting for security purposes
* File parsing and regular expressions
* Basic threat detection logic
* Writing clean and readable CLI tools

---

## Project Structure

```
loginspector/
├── loginspector.py              ← Main log analyzer script
├── sample_logs/
│   ├── winlog_sample.txt        ← Sample Windows Security Event Logs
│   └── linux_syslog_sample.txt  ← Sample Linux syslogs
├── findings/
│   └── suspicious_output.txt    ← Output of flagged results
├── README.md
└── requirements.txt
```

---

## How to Run

```bash
# Clone the repo
$ git clone https://github.com/yourname/loginspector.git
$ cd loginspector

# Create a virtual environment (optional)
$ python -m venv venv
$ source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
$ pip install -r requirements.txt

# Run analysis
$ python loginspector.py sample_logs/winlog_sample.txt
```

---

## 🔍 Example Findings (Terminal Output)

```
[!] Suspicious login failure detected (Event ID 4625)
    ➤ Account: juser1
    ➤ Time: 2025-05-08T09:06:10

[!] Encoded PowerShell command execution found
    ➤ Command Line: powershell.exe -nop -enc SQBtAHAAbwByAHQALQBNAG8AZAB1AGwAZQAgAFcAaQBuADMAMgAuAEQAbABsAA==
    ➤ Decoded: Import-Module Win32.Dll (Used to load external modules, may indicate attacker attempting to extend PowerShell capabilities)
```

---

## 🧾 Sample Detection Logic (Excerpt from `loginspector.py`)

```python
import re
import sys

def scan_log(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if 'Event ID: 4625' in line:
            print("[!] Suspicious login failure detected (Event ID 4625)")
            print(f"    ➤ Line: {i+1}: {line.strip()}")

        if re.search(r"powershell.*-enc", line, re.IGNORECASE):
            print("[!] Encoded PowerShell command execution found")
            print(f"    ➤ Line: {i+1}: {line.strip()}")
```

---

## ✅ Requirements

```
# requirements.txt
colorama
```

---

## Sample Input (`winlog_sample.txt`)

```
Event ID: 4625
Account Failed To Logon: juser1
Time: 2025-05-08T09:06:10
Command: powershell.exe -enc SQBtAHAAbwByAHQALQBNAG8AZAB1AGwAZQAgAFcAaQBuADMAMgAuAEQAbABsAA==
# Encoded Command decodes to: Import-Module Win32.Dll
```

---

## Next Steps / Ideas

* Add JSON output mode for SIEM ingestion
* Support log filtering by time or event ID
* Add hash/IOC scanning using public threat feeds


---

