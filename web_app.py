from flask import Flask, request, jsonify, render_template
import os
import json
import uuid
import yaml
import threading
from datetime import datetime
from scanner import Scanner
from rule_engine import RuleEngine

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
DATA_FILE = "scans.json"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

engine = RuleEngine()
scanner = Scanner(engine.rules)


# -------------------------------------------------
# Helpers
# -------------------------------------------------

def load_scans():
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r") as f:
        return json.load(f)


def save_scans(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)


def calculate_risk(summary):
    priority = ["Critical", "High", "Medium", "Low"]
    for p in priority:
        if p in summary:
            return p
    return "Low"


# -------------------------------------------------
# Routes
# -------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# -------- Upload & Scan --------
@app.route("/scan", methods=["POST"])
def scan_apk():

    if "apk" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    apk = request.files["apk"]
    scan_id = str(uuid.uuid4())

    filename = f"{scan_id}_{apk.filename}"
    path = os.path.join(UPLOAD_FOLDER, filename)
    apk.save(path)

    scans = load_scans()

    new_scan = {
        "id": scan_id,
        "filename": apk.filename,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "Running",
        "summary": {},
        "findings": [],
        "risk": "Low"
    }

    scans.insert(0, new_scan)
    save_scans(scans)

    # 🔥 Background worker
    def background_scan():

        try:
            findings, summary, _ = scanner.scan(path)
        except Exception as e:
            print("SCAN ERROR:", e)
            findings = []
            summary = {}

        scans = load_scans()

        for s in scans:
            if s["id"] == scan_id:
                s["status"] = "Done"
                s["summary"] = summary
                s["findings"] = findings
                s["risk"] = calculate_risk(summary)
                break

        save_scans(scans)

    thread = threading.Thread(target=background_scan)
    thread.start()

    return jsonify({"status": "started"})


# -------- History --------
@app.route("/history")
def history():
    return jsonify(load_scans())


# -------- Scan Detail --------
@app.route("/scan/<scan_id>")
def scan_detail(scan_id):
    scans = load_scans()
    for s in scans:
        if s["id"] == scan_id:
            return jsonify(s)
    return jsonify({"error": "Not found"}), 404


# -------- Delete --------
@app.route("/delete/<scan_id>", methods=["POST"])
def delete_scan(scan_id):
    scans = load_scans()
    scans = [s for s in scans if s["id"] != scan_id]
    save_scans(scans)
    return jsonify({"status": "deleted"})


# -------- Exploit --------
@app.route("/exploit/<rule_name>")
def get_exploit(rule_name):

    exploit_path = os.path.join("rules", "exploit.yaml")

    if not os.path.exists(exploit_path):
        return jsonify({"error": "exploit.yaml not found"}), 404

    with open(exploit_path, "r") as f:
        exploits = yaml.safe_load(f)

    if rule_name not in exploits:
        return jsonify({"error": "No exploit steps found"}), 404

    return jsonify({
        "rule": rule_name,
        "steps": exploits[rule_name]
    })


# -------------------------------------------------

if __name__ == "__main__":
    app.run(port=8000)
