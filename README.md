# 🚀 APKSensify

![CI](https://github.com/JerryShah3/apksensify/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Docker](https://img.shields.io/badge/docker-supported-blue)
![Status](https://img.shields.io/badge/status-active-brightgreen)

---

## 🔍 Android Static Security Analyzer

**APKSensify** is an open-source Android Static Security Analyzer designed to detect exposed secrets and security misconfigurations inside APK files.

It performs static analysis by decompiling APKs using `apktool` and scanning source resources using custom rule-based regex detection.

---

## ✨ Features

- 🔍 Static secret detection (API keys, Firebase URLs, AppSpot domains, etc.)
- 🧠 Regex-based rule engine
- 🎨 Rich CLI output with severity classification
- 📄 HTML report generation
- 🛡 SARIF report generation (for GitHub Code Scanning)
- ⚡ Smart caching system
- 🌐 Optional Web UI interface
- 🐳 Docker support
- 🧨 Exploit guidance support (rule-based) (coming soon)

---

# 🏗 How It Works

1. Decompiles APK using `apktool`
2. Walks through decompiled files
3. Applies regex rules from `rules/`
4. Generates findings categorized by severity
5. Outputs results in CLI, JSON, HTML, or SARIF format

---

# 📦 Installation

## 🔧 Requirements

- Python 3.10+
- OpenJDK 17+
- apktool
- unzip

---

## 🛠 Install Dependencies

```bash
git clone https://github.com/JerryShah3/apksensify.git
cd apksensify
pip install -r requirements.txt
```

🛠 Install apktool (Linux)

```
sudo apt install apktool openjdk-17-jre unzip
```

🧪 CLI Usage

```
python3 apksensify.py [options] <apk>
```
📘 CLI Manual (Flags Explained)

📌 Basic Scan

```
python3 apksensify.py sample.apk
```
Runs a static scan on the APK and prints findings in formatted CLI output.

🔎 --json

```
python3 apksensify.py sample.apk --json
```
Outputs results in raw JSON format.

Useful for:

Automation

CI/CD pipelines

Script integration

📄 --html

```
python3 apksensify.py sample.apk --html
```

Generates an HTML report:

report.html

Useful for:

Sharing results

Client reports

Documentation

🛡 --sarif

```
python3 apksensify.py sample.apk --sarif

Generates SARIF output:

report.sarif

Useful for:

GitHub Code Scanning

DevSecOps workflows

CI integration
```

⚡ --no-cache
python3 apksensify.py sample.apk --no-cache

Forces a fresh scan and ignores cached results.

Default behavior:

APKSensify hashes the APK

If results exist in .cache/, they are reused

Use this flag when:

Rules are updated

You want guaranteed fresh analysis

🧨 --exploit <rule_name>
python3 apksensify.py --exploit Google_API

Displays exploit steps for a specific rule.

Exploit steps are defined inside:

rules/exploit.yaml

This mode does NOT scan an APK.
It only shows exploitation guidance.


🧾 Exit Codes

| Code | Meaning                              |
| ---- | ------------------------------------ |
| 0    | Scan completed, no critical findings |
| 2    | Critical finding detected            |
| 1    | Error occurred                       |
Useful for CI/CD pipelines.

🌐 Web UI

Start server:
python3 web_app.py

Open:

http://127.0.0.1:8000
Web Features

Drag & drop APK upload

Live scan status

Findings modal view

Collapsible exploit panel

Scan history

Delete scan option

🐳 Docker Usage

Build image:

docker build -t apksensify .

Run scan:

docker run --rm -v $(pwd):/app apksensify sample.apk

apksensify/
│
├── apksensify.py
├── web_app.py
├── scanner.py
├── rule_engine.py
├── requirements.txt
├── Dockerfile
│
├── rules/
│   ├── secrets.yaml
│   └── exploit.yaml
│
├── templates/
│   └── report.html
│
├── static/
├── uploads/
├── .cache/
└── scans.json

🧠 Writing Custom Rules

Rules are defined in:

rules/*.yaml

Example:

Google_API:
  regex: "AIza[0-9A-Za-z-_]{35}"
  severity: "low"
  description: "Google API Key detected"

Fields:

regex → detection pattern

severity → critical / high / medium / low

NOTE: Severity is tend to change based on the exploitation scenario

description → optional

🔮 Roadmap

Planned features:

Root detection logic

SSL pinning detection

Insecure deep link detection

Performance optimization

🤝 Contributing

Fork the repository

Create a feature branch

Commit changes

Open a pull request

🛡 Security Disclaimer

This tool is intended for:

Security research

Educational purposes

Authorized penetration testing

Do not scan applications without permission.

📜 License

MIT License

👤 Author

Jerry Shah
Security Researcher

GitHub: https://github.com/JerryShah3

⭐ Support

If you find this project useful:

⭐ Star the repository

🐛 Report issues

📢 Share on LinkedIn or Twitter
