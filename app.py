from flask import Flask, render_template, request, redirect
from modules.hasher import hash_text, hash_file
from modules.phishing import check_url
from modules.db import (init_db, add_alert, get_alerts, count_by_source,
                        count_by_severity, clear_alerts)

app = Flask(__name__)
init_db()

@app.route("/")
def home():
    by_source = dict(count_by_source())
    by_severity = dict(count_by_severity())
    total = sum(by_source.values())
    return render_template("home.html", total=total, by_source=by_source,
                           by_severity=by_severity, recent=get_alerts(5))

@app.route("/hash", methods=["GET", "POST"])
def hash_page():
    results = None
    text = ""
    if request.method == "POST":
        text = request.form["text"]
        results = hash_text(text)
    return render_template("hash.html", results=results, text=text)

@app.route("/hash-file", methods=["GET", "POST"])
def hash_file_page():
    results = None
    filename = ""
    matched = None
    checked = False
    if request.method == "POST":
        uploaded = request.files["file"]
        filename = uploaded.filename
        results = hash_file(uploaded.stream)
        expected = request.form.get("expected", "").strip().lower()
        if expected:
            checked = True
            for name, value in results.items():
                if value == expected:
                    matched = name
    return render_template("hashfile.html", results=results, filename=filename,
                           matched=matched, checked=checked)

@app.route("/phishing", methods=["GET", "POST"])
def phishing_page():
    result = None
    url = ""
    if request.method == "POST":
        url = request.form["url"]
        result = check_url(url)
        if result["verdict"] != "Looks safe":
            severity = "high" if result["verdict"] == "Likely phishing" else "medium"
            add_alert("Phishing detector", severity,
                      url + " | " + result["verdict"] + " (" + str(result["percent"]) + "%)")
    return render_template("phishing.html", result=result, url=url)

@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html", alerts=get_alerts())

@app.route("/alerts/clear", methods=["POST"])
def alerts_clear():
    clear_alerts()
    return redirect("/alerts")

if __name__ == "__main__":
    app.run(debug=True)