import argparse
import base64
import hashlib
import hmac
import io
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

import pyotp
import qrcode
from flask import Flask, jsonify, render_template_string, request


DB_FILE = "/var/lib/api-2fa/users.db"

app = Flask(__name__)


# ============================================================
# Database
# ============================================================

def db():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_challenges (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# Password hashing
# ============================================================

def hash_password(password):
    salt = os.urandom(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        300_000
    )

    return salt.hex() + "$" + digest.hex()


def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)

        salt = bytes.fromhex(salt_hex)

        calculated = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            300_000
        )

        return hmac.compare_digest(
            calculated.hex(),
            digest_hex
        )

    except Exception:
        return False


# ============================================================
# Time
# ============================================================

def now_ts():
    return int(datetime.now(timezone.utc).timestamp())


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        admin_password = os.environ.get("API_ADMIN_PASSWORD")
        if not admin_password:
            return jsonify({
                "result": "Fail",
                "message": "user management is disabled; set API_ADMIN_PASSWORD"
            }), 503

        auth = request.authorization
        if (
            not auth
            or not hmac.compare_digest(auth.username.encode(), b"admin")
            or not hmac.compare_digest(
                auth.password.encode(), admin_password.encode()
            )
        ):
            response = jsonify({
                "result": "Fail",
                "message": "admin authentication required"
            })
            response.status_code = 401
            response.headers["WWW-Authenticate"] = 'Basic realm="2FA user management"'
            return response

        return view(*args, **kwargs)

    return wrapped


def user_totp_data(username, secret):
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="Lab-API-2FA"
    )
    image = qrcode.make(uri)
    output = io.BytesIO()
    image.save(output, format="PNG")

    return {
        "totp_secret": secret,
        "otpauth_uri": uri,
        "qr_code": "data:image/png;base64," + base64.b64encode(
            output.getvalue()
        ).decode("ascii")
    }


@app.get("/manage")
def manage_page():
        return render_template_string("""
<!doctype html>
<html lang="th">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>จัดการผู้ใช้ | API 2FA</title>
    <style>
        :root { color-scheme: light; font-family: "Segoe UI", Tahoma, sans-serif; color: #172b35; background: #edf3f1; }
        * { box-sizing: border-box; }
        body { margin: 0; min-height: 100vh; background: linear-gradient(135deg, #e9f3ef, #f5f2e9 60%, #e8eff1); }
        header { background: #123b3a; color: white; padding: 22px max(20px, calc((100% - 1100px) / 2)); }
        header h1 { font-size: 23px; margin: 0; font-weight: 650; }
        main { max-width: 1100px; margin: 26px auto; padding: 0 20px 48px; }
        section { background: #fff; border: 1px solid #d8e2de; border-radius: 6px; padding: 20px; margin-bottom: 18px; box-shadow: 0 5px 18px #123b3a0b; }
        h2 { font-size: 17px; margin: 0 0 16px; }
        form { display: flex; flex-wrap: wrap; align-items: end; gap: 12px; }
        label { display: grid; gap: 6px; font-size: 13px; color: #40565a; }
        input { min-height: 39px; border: 1px solid #bacbc5; border-radius: 4px; padding: 8px 10px; font: inherit; }
        button { min-height: 38px; border: 0; border-radius: 4px; padding: 8px 13px; font: inherit; font-weight: 600; color: white; background: #16736c; cursor: pointer; }
        button:hover { background: #105b56; }
        button.secondary { color: #214b4a; background: #e4efeb; }
        button.danger { color: #8a302d; background: #fae9e6; }
        #status { min-height: 22px; color: #9a332e; font-size: 14px; margin: 10px 0 0; }
        .table-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; min-width: 720px; }
        th, td { text-align: left; vertical-align: middle; border-bottom: 1px solid #e3eae7; padding: 12px 10px; }
        th { color: #59706c; font-size: 12px; font-weight: 650; }
        td { font-size: 14px; }
        td small { display: block; color: #68807a; margin-top: 4px; }
        td code { overflow-wrap: anywhere; color: #234f4b; }
        .qr { width: 116px; height: 116px; object-fit: contain; image-rendering: pixelated; }
        .actions { display: flex; gap: 7px; flex-wrap: wrap; }
        @media (max-width: 600px) { main { margin-top: 16px; padding-inline: 12px; } section { padding: 15px; } form > label { flex: 1 1 100%; } form input { width: 100%; } }
    </style>
</head>
<body>
    <header><h1>จัดการผู้ใช้ · API 2FA</h1></header>
    <main>
        <section>
            <h2>ผู้ดูแลระบบ</h2>
            <form id="auth-form">
                <label>รหัสผ่านแอดมิน<input id="admin-password" type="password" autocomplete="current-password" required></label>
                <button type="submit">เข้าสู่ระบบ</button>
            </form>
            <p id="status" role="status"></p>
        </section>
        <section>
            <h2>เพิ่มผู้ใช้</h2>
            <form id="create-form">
                <label>ชื่อผู้ใช้<input name="username" maxlength="64" required></label>
                <label>รหัสผ่านเริ่มต้น<input name="password" type="password" minlength="4" required></label>
                <button type="submit">เพิ่มผู้ใช้</button>
            </form>
        </section>
        <section>
            <h2>บัญชีผู้ใช้และ OTP</h2>
            <div class="table-wrap"><table>
                <thead><tr><th>ผู้ใช้</th><th>รหัสลับ OTP</th><th>QR สำหรับ Authenticator</th><th>จัดการ</th></tr></thead>
                <tbody id="users"><tr><td colspan="4">กรุณาเข้าสู่ระบบแอดมิน</td></tr></tbody>
            </table></div>
        </section>
    </main>
    <script>
        let adminPassword = "";
        const status = document.querySelector("#status");
        const usersBody = document.querySelector("#users");
        function authHeader() {
            const bytes = new TextEncoder().encode("admin:" + adminPassword);
            let binary = "";
            bytes.forEach(byte => binary += String.fromCharCode(byte));
            return "Basic " + btoa(binary);
        }
        async function api(path, options = {}) {
            const response = await fetch(path, {
                ...options,
                headers: { "Authorization": authHeader(), ...(options.headers || {}) }
            });
            const body = await response.json();
            if (!response.ok) throw new Error(body.message || "คำขอไม่สำเร็จ");
            return body;
        }
        function renderUsers(users) {
            usersBody.replaceChildren();
            if (!users.length) {
                const row = usersBody.insertRow();
                const cell = row.insertCell(); cell.colSpan = 4; cell.textContent = "ยังไม่มีผู้ใช้";
                return;
            }
            users.forEach(user => {
                const row = usersBody.insertRow();
                const name = row.insertCell(); name.textContent = user.username;
                const created = document.createElement("small"); created.textContent = user.created_at;
                name.append(created);
                const secretCell = row.insertCell();
                const secret = document.createElement("code"); secret.textContent = user.totp_secret;
                secretCell.append(secret);
                const qrCell = row.insertCell();
                const image = document.createElement("img"); image.className = "qr";
                image.alt = "QR สำหรับ " + user.username; image.src = user.qr_code; qrCell.append(image);
                const actions = row.insertCell(); actions.className = "actions";
                const change = document.createElement("button"); change.className = "secondary";
                change.textContent = "เปลี่ยนรหัสผ่าน";
                change.addEventListener("click", async () => {
                    const password = prompt("รหัสผ่านใหม่ (อย่างน้อย 4 ตัวอักษร)");
                    if (password === null) return;
                    try {
                        await api("/api/users/" + encodeURIComponent(user.username) + "/password", {
                            method: "PATCH", headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ password })
                        });
                        status.textContent = "เปลี่ยนรหัสผ่านแล้ว";
                    } catch (error) { status.textContent = error.message; }
                });
                const remove = document.createElement("button"); remove.className = "danger";
                remove.textContent = "ลบผู้ใช้";
                remove.addEventListener("click", async () => {
                    if (!confirm("ยืนยันลบบัญชี " + user.username + " ?")) return;
                    try {
                        await api("/api/users/" + encodeURIComponent(user.username), { method: "DELETE" });
                        await loadUsers(); status.textContent = "ลบผู้ใช้แล้ว";
                    } catch (error) { status.textContent = error.message; }
                });
                actions.append(change, remove);
            });
        }
        async function loadUsers() { renderUsers((await api("/api/users")).users); }
        document.querySelector("#auth-form").addEventListener("submit", async event => {
            event.preventDefault(); adminPassword = document.querySelector("#admin-password").value;
            try { await loadUsers(); status.textContent = "เข้าสู่ระบบแล้ว"; }
            catch (error) { adminPassword = ""; status.textContent = error.message; }
        });
        document.querySelector("#create-form").addEventListener("submit", async event => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            try {
                await api("/api/users", {
                    method: "POST", headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username: form.get("username"), password: form.get("password") })
                });
                event.currentTarget.reset(); await loadUsers(); status.textContent = "เพิ่มผู้ใช้แล้ว สแกน QR ในตารางด้วย Authenticator";
            } catch (error) { status.textContent = error.message; }
        });
    </script>
</body>
</html>
        """)


# ============================================================
# 1. Username / Password
# ============================================================

@app.post("/api/login")
def login():

    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")

    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not username
        or not password
    ):
        return jsonify({
            "result": "Fail",
            "message": "username and password required"
        }), 400

    conn = db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
          AND enabled = 1
        """,
        (username,)
    ).fetchone()

    conn.close()

    if not user or not verify_password(
        password,
        user["password_hash"]
    ):
        return jsonify({
            "result": "Fail",
            "message": "invalid username or password"
        }), 401

    # Create temporary challenge.
    challenge = secrets.token_urlsafe(32)

    conn = db()

    conn.execute(
        """
        INSERT INTO login_challenges
        (id, username, expires_at)
        VALUES (?, ?, ?)
        """,
        (
            challenge,
            username,
            now_ts() + 300
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "result": "Success",
        "stage": "2fa_required",
        "username": username,
        "challenge": challenge,
        "expires_in": 300
    })


# ============================================================
# 2. TOTP 2FA
# ============================================================

@app.post("/api/2fa")
def verify_2fa():

    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    code = str(data.get("code", ""))
    challenge = data.get("challenge", "")

    if not username or not code or not challenge:
        return jsonify({
            "result": "Fail",
            "message": "username, code and challenge required"
        }), 400

    conn = db()

    row = conn.execute(
        """
        SELECT *
        FROM login_challenges
        WHERE id = ?
          AND username = ?
          AND used = 0
        """,
        (challenge, username)
    ).fetchone()

    if not row:
        conn.close()

        return jsonify({
            "result": "Fail",
            "message": "invalid challenge"
        }), 401

    if row["expires_at"] < now_ts():

        conn.execute(
            """
            UPDATE login_challenges
            SET used = 1
            WHERE id = ?
            """,
            (challenge,)
        )

        conn.commit()
        conn.close()

        return jsonify({
            "result": "Fail",
            "message": "challenge expired"
        }), 401

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
          AND enabled = 1
        """,
        (username,)
    ).fetchone()

    if not user:
        conn.close()

        return jsonify({
            "result": "Fail",
            "message": "user not found"
        }), 401

    totp = pyotp.TOTP(user["totp_secret"])

    # valid_window=1 allows +/- one 30-second period
    valid = totp.verify(
        code,
        valid_window=1
    )

    if not valid:
        conn.close()

        return jsonify({
            "result": "Fail",
            "message": "invalid 2fa code"
        }), 401

    # One-time challenge.
    conn.execute(
        """
        UPDATE login_challenges
        SET used = 1
        WHERE id = ?
        """,
        (challenge,)
    )

    conn.commit()
    conn.close()

    # For the lab, return a simple access token.
    access_token = secrets.token_urlsafe(32)

    return jsonify({
        "result": "Success",
        "username": username,
        "access_token": access_token,
        "message": "authentication successful"
    })


# ============================================================
# 3. Add user
# ============================================================

@app.get("/api/users")
@admin_required
def list_users():
    conn = db()
    users = conn.execute(
        "SELECT username, totp_secret, created_at FROM users ORDER BY username"
    ).fetchall()
    conn.close()

    return jsonify({
        "result": "Success",
        "users": [
            {
                "username": user["username"],
                "created_at": user["created_at"],
                **user_totp_data(user["username"], user["totp_secret"])
            }
            for user in users
        ]
    })


@app.post("/api/users")
@admin_required
def add_user():

    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")

    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not username
        or not password
    ):
        return jsonify({
            "result": "Fail",
            "message": "username and password required"
        }), 400

    if len(username) > 64:
        return jsonify({
            "result": "Fail",
            "message": "username too long"
        }), 400

    if len(password) < 4:
        return jsonify({
            "result": "Fail",
            "message": "password must be at least 4 characters"
        }), 400

    # Generate TOTP secret.
    secret = pyotp.random_base32()

    conn = db()

    try:

        conn.execute(
            """
            INSERT INTO users
            (
                username,
                password_hash,
                totp_secret,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                username,
                hash_password(password),
                secret,
                datetime.now(timezone.utc).isoformat()
            )
        )

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return jsonify({
            "result": "Fail",
            "message": "user already exists"
        }), 409

    conn.close()

    return jsonify({
        "result": "Success",
        "username": username,
        **user_totp_data(username, secret),

        "message": "user created"
    }), 201


@app.patch("/api/users/<username>/password")
@admin_required
def change_user_password(username):
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not isinstance(password, str) or len(password) < 4:
        return jsonify({
            "result": "Fail",
            "message": "password must be at least 4 characters"
        }), 400

    conn = db()
    user = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    if not user:
        conn.close()
        return jsonify({"result": "Fail", "message": "user not found"}), 404

    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (hash_password(password), user["id"])
    )
    conn.execute("DELETE FROM login_challenges WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    return jsonify({"result": "Success", "message": "password updated"})


@app.delete("/api/users/<username>")
@admin_required
def delete_user(username):
    conn = db()
    cursor = conn.execute("DELETE FROM users WHERE username = ?", (username,))
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({"result": "Fail", "message": "user not found"}), 404

    conn.execute("DELETE FROM login_challenges WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    return jsonify({"result": "Success", "message": "user deleted"})


# ============================================================
# 4. User information
# ============================================================

@app.get("/api/users/<username>")
def user_info(username):

    conn = db()

    user = conn.execute(
        """
        SELECT
            username,
            enabled,
            created_at
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    conn.close()

    if not user:
        return jsonify({
            "result": "Fail",
            "message": "user not found"
        }), 404

    return jsonify({
        "result": "Success",
        "user": dict(user)
    })


# ============================================================
# Health check
# ============================================================

@app.get("/health")
def health():

    return jsonify({
        "result": "Success",
        "service": "api-2fa"
    })


# ============================================================
# Main
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description="Lab API Username/Password + TOTP 2FA"
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=5001
    )

    args = parser.parse_args()

    init_db()

    print(
        f"API 2FA listening on "
        f"http://{args.host}:{args.port}"
    )

    app.run(
        host=args.host,
        port=args.port,
        debug=False
    )


if __name__ == "__main__":
    main()
