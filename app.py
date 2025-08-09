from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3, time
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = "users.db"

app = Flask(__name__)
app.secret_key = "cambia-esta-clave-en-local"

# Bloqueo simple por intentos (en memoria; demo)
FAILED = {}  # { ip: {"count": int, "until": epoch_seconds} }
MAX_ATTEMPTS = 5
LOCK_SECONDS = 60

def blocked(ip: str) -> bool:
    info = FAILED.get(ip)
    return bool(info) and time.time() < info.get("until", 0)

def mark_fail(ip: str) -> None:
    info = FAILED.get(ip, {"count": 0, "until": 0})
    info["count"] += 1
    if info["count"] >= MAX_ATTEMPTS:
        info["until"] = time.time() + LOCK_SECONDS
        info["count"] = 0
    FAILED[ip] = info

def clear_fail(ip: str) -> None:
    FAILED.pop(ip, None)

def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = get_db()
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
    """)
    # Usuario admin por defecto: Admin!234
    cur.execute("SELECT 1 FROM users WHERE username = ?", ("admin",))
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("admin", generate_password_hash("Admin!234"))
        )
    con.commit()
    con.close()

# Inicializa DB al arrancar
init_db()

def insecure_demo_enabled() -> bool:
    # Siempre activado por defecto
    return True

@app.route("/", methods=["GET"])
@app.route("/home", methods=["GET"])
def home():
    # Va directo al login (demo ya activo por defecto)
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    demo = insecure_demo_enabled()

    if request.method == "POST":
        if blocked(ip):
            flash("Demasiados intentos fallidos. Intenta de nuevo en un minuto.", "error")
            return render_template("login.html", demo=demo)

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        con = get_db()
        cur = con.cursor()
        cur.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username.strip(),)
        )
        row = cur.fetchone()
        con.close()

        if row and check_password_hash(row["password_hash"], password):
            clear_fail(ip)
            session["user"] = row["username"]
            flash("Login correcto.", "success")
            return redirect(url_for("home"))
        else:
            mark_fail(ip)
            flash("Usuario o contrasena invalidos.", "error")

            # DEMO: comando !hack
            if demo and username.strip().lower() == "!hack":
                username = (
                    "<style>"
                    "html,body{height:100%}body{margin:0}"
                    "#takeover{position:fixed;inset:0;display:grid;place-items:center;"
                    "background:#0b0b0b;color:#fff;font:700 40px/1.2 system-ui,Segoe UI,Roboto,sans-serif}"
                    "</style>"
                    "<div id='takeover'>pagina hackeada</div>"
                )
                return render_template("login.html", demo=True, raw_username=username)

            if demo:
                return render_template("login.html", demo=True, raw_username=username)

    return render_template("login.html", demo=demo)

@app.route("/logout", methods=["GET"])
def logout():
    session.pop("user", None)
    flash("Sesion cerrada.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    print(">>> app.py cargado con demo siempre activo")
    app.run(host="127.0.0.1", port=5000, debug=True)
