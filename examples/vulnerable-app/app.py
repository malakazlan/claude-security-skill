"""
DELIBERATELY VULNERABLE demo app for claude-security.

Do NOT deploy this. It exists so the scanner catches real issues on first run:
  1. Hardcoded secret (secrets scanner + SAST)
  2. SQL injection via string formatting (SAST: semgrep/bandit)
  3. Missing ownership/authorization check (AI semantic pass — IDOR)
"""

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# [VULN 1] Hardcoded secret — should be in a secret manager / env var.
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLEKEYab/cdEFghijKLmnoPQRstuvWXyz12"
app.config["SECRET_KEY"] = "super-secret-hardcoded-key-do-not-do-this"


def get_db():
    return sqlite3.connect("app.db")


@app.route("/user/<user_id>/search")
def search_orders(user_id):
    # [VULN 2] SQL injection — user input concatenated straight into the query.
    q = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    query = "SELECT * FROM orders WHERE user_id = '%s' AND name LIKE '%%%s%%'" % (user_id, q)
    cur.execute(query)
    rows = cur.fetchall()
    return jsonify(rows)


@app.route("/order/<order_id>/delete", methods=["POST"])
def delete_order(order_id):
    # [VULN 3] Broken access control (IDOR): deletes ANY order by id with no
    # check that the current user owns it. A static scanner won't flag this —
    # the code is "correct"; the authorization is simply missing.
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    return jsonify({"deleted": order_id})


if __name__ == "__main__":
    # [VULN 4] debug=True in production leaks the interactive debugger.
    app.run(debug=True, host="0.0.0.0")
