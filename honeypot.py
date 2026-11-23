from flask import Flask, render_template, request
from modules.db import init_db, add_alert

app = Flask(__name__)
init_db()

attempts = {}


@app.route("/", methods=["GET", "POST"])
@app.route("/admin", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def fake_login():
    error = None
    if request.method == "POST":
        ip = request.remote_addr
        username = request.form.get("username", "")[:50]
        password = request.form.get("password", "")[:50]
        agent = request.headers.get("User-Agent", "unknown")[:80]

        attempts[ip] = attempts.get(ip, 0) + 1
        count = attempts[ip]

        if count >= 5:
            severity = "high"
            note = "possible brute force, attempt " + str(count)
        else:
            severity = "medium"
            note = "attempt " + str(count)

        details = ("IP " + ip + " tried username '" + username +
                   "' and password '" + password + "' (" + note + ") | " + agent)
        add_alert("Honeypot", severity, details)

        error = "Invalid username or password."
    return render_template("fake_login.html", error=error)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)