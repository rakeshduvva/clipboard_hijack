from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
import os, csv, json, time
from datetime import datetime
import pyperclip

APP_ROOT = os.path.dirname(__file__)
LOG_CSV = os.path.join(APP_ROOT, "logs.csv")
TRUSTED_JSON = os.path.join(APP_ROOT, "trusted.json")
TX_JSON = os.path.join(APP_ROOT, "transactions.json")

app = Flask(__name__, static_folder="static", template_folder="templates")

# --------- File Setup & Helpers ----------

def ensure_files():
    """Ensure all storage files exist"""
    if not os.path.exists(LOG_CSV):
        with open(LOG_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "event", "prev_clip", "new_clip", "meta"])

    if not os.path.exists(TRUSTED_JSON):
        with open(TRUSTED_JSON, "w", encoding="utf-8") as f:
            json.dump({"trusted": []}, f, indent=2)

    if not os.path.exists(TX_JSON):
        with open(TX_JSON, "w", encoding="utf-8") as f:
            json.dump({"tx": []}, f, indent=2)


def log_event(event, prev, new, meta=""):
    """Append a log entry to CSV"""
    ensure_files()
    ts = datetime.utcnow().isoformat() + "Z"
    with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([ts, event, prev, new, meta])


def read_logs(limit=200):
    """Read recent logs"""
    ensure_files()
    rows = []
    with open(LOG_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows[-limit:][::-1]


def read_trusted():
    ensure_files()
    with open(TRUSTED_JSON, "r", encoding="utf-8") as f:
        return json.load(f).get("trusted", [])


def save_trusted(values):
    with open(TRUSTED_JSON, "w", encoding="utf-8") as f:
        json.dump({"trusted": values}, f, indent=2)


def add_transaction(address):
    ensure_files()
    tx = {
        "id": int(time.time()),
        "address": address,
        "status": "success",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    with open(TX_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)
    data["tx"].append(tx)

    with open(TX_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return tx

# --------- Routes ----------

@app.route("/")
def index():
    ensure_files()
    try:
        current_clipboard = pyperclip.paste()
    except Exception:
        current_clipboard = "(Clipboard access denied)"
    return render_template("index.html", current_clipboard=current_clipboard)


@app.route("/api/clipboard", methods=["GET"])
def api_clipboard():
    try:
        text = pyperclip.paste()
    except Exception:
        text = ""
    return jsonify({"clipboard": text})


@app.route("/api/capture", methods=["POST"])
def api_capture():
    data = request.json or {}
    addr = data.get("address", "").strip()
    if not addr:
        return jsonify({"ok": False, "msg": "No address provided"}), 400

    trusted = read_trusted()
    if addr not in trusted:
        trusted.append(addr)
        save_trusted(trusted)
        log_event("trusted_added", "", addr, "added_via_web")

    return jsonify({"ok": True, "trusted": trusted})


@app.route("/trusted")
def trusted_page():
    trusted = read_trusted()
    return render_template("trusted.html", trusted=trusted)


@app.route("/trusted/remove", methods=["POST"])
def trusted_remove():
    addr = request.form.get("address", "").strip()
    trusted = read_trusted()
    if addr in trusted:
        trusted.remove(addr)
        save_trusted(trusted)
        log_event("trusted_removed", "", addr, "removed_via_web")
    return redirect(url_for("trusted_page"))


@app.route("/logs")
def logs_page():
    logs = read_logs(200)
    return render_template("logs.html", logs=logs)


@app.route("/transact", methods=["GET", "POST"])
def transact():
    if request.method == "POST":
        addr = request.form.get("address", "").strip()
        if not addr:
            return render_template("transact.html", error="Paste a Bitcoin/Ethereum address to continue.")

        tx = add_transaction(addr)
        log_event("transaction_simulated", "", addr, f"txid:{tx['id']}")
        return render_template("transact.html", success=True, tx=tx)

    return render_template("transact.html")

@app.route("/api/trusted_sync", methods=["POST"])
def trusted_sync():
    data = request.json or {}
    addr = data.get("address", "")
    if not addr:
        return jsonify({"ok": False}), 400
    trusted = read_trusted()
    if addr not in trusted:
        trusted.append(addr)
        save_trusted(trusted)
    log_event("trusted_synced", "", addr, "synced_from_monitor")
    return jsonify({"ok": True})

@app.route("/api/untrusted_sync", methods=["POST"])
def untrusted_sync():
    data = request.json or {}
    addr = data.get("address", "")
    log_event("untrusted_detected", "", addr, "detected_from_monitor")
    return jsonify({"ok": True})


@app.route("/logs/clear", methods=["POST"])
def clear_logs():
    ensure_files()
    try:
        # Overwrite CSV with header only
        with open(LOG_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "event", "prev_clip", "new_clip", "meta"])
        
        # Log that logs were cleared
        log_event("logs_cleared", "", "", "Cleared all logs via web")
        return redirect(url_for("logs_page"))
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500


@app.route("/api/logs")
def api_logs():
    return jsonify(read_logs(200))


@app.route("/api/transactions")
def api_transactions():
    ensure_files()
    with open(TX_JSON, "r", encoding="utf-8") as f:
        return jsonify(json.load(f))


@app.route("/download/logs")
def download_logs():
    if not os.path.exists(LOG_CSV):
        ensure_files()
    return send_file(LOG_CSV, as_attachment=True)


@app.errorhandler(404)
def not_found(e):
    return redirect("/")


if __name__ == "__main__":
    ensure_files()
    app.run(debug=True, port=5000)
