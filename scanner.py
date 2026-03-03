import os
import subprocess
import shutil
import re

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB


class Scanner:

    def __init__(self, rules):
        self.rules = rules

    def scan(self, apk_path):

        findings = []
        summary = {}
        critical_found = False

        decompiled_dir = apk_path.replace(".apk", "_decompiled")

        if os.path.exists(decompiled_dir):
            shutil.rmtree(decompiled_dir, ignore_errors=True)

        # 🔥 DO NOT CAPTURE OUTPUT IN THREAD
        result = subprocess.run(
            ["apktool", "-f", "d", "-s", apk_path, "-o", decompiled_dir],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if result.returncode != 0:
            print("APKTOOL FAILED")
            return [], {}, False

        for root, _, files in os.walk(decompiled_dir):
            for file in files:

                if file.endswith((".dex", ".so", ".png", ".jpg", ".jpeg", ".webp")):
                    continue

                file_path = os.path.join(root, file)

                if os.path.getsize(file_path) > MAX_FILE_SIZE:
                    continue

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except:
                    continue

                for rule_name, rule in self.rules.items():
                    try:
                        matches = rule["pattern"].findall(content)
                    except re.error:
                        continue

                    if matches:
                        severity = rule["severity"]
                        severity_display = severity.capitalize()

                        summary[severity_display] = summary.get(severity_display, 0) + len(matches)

                        if severity.lower() == "critical":
                            critical_found = True

                        findings.append({
                            "rule": rule_name,
                            "severity": severity_display,
                            "file": file_path,
                            "matches": matches
                        })

        return findings, summary, critical_found
