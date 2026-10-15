"""
LectureHub backend. Same flow map REA surfaced in the original app
(register, login, forgot/change password, sessions, tags, favorites,
bookmarks, settings, subscription), rebuilt as a small clean server.

Run:  python3 server.py           (listens on 0.0.0.0:8090)
Needs: flask  ->  pip install flask

Passwords are salted-hashed (PBKDF2). Auth is a bearer token.
"""

import hashlib, os, secrets, sqlite3
from flask import Flask, jsonify, request

DB_PATH = os.environ.get("LECTUREHUB_DB", "lecturehub.db")
BASE_URL = os.environ.get("LECTUREHUB_BASE_URL", "http://YOUR_HOST:8090")

app = Flask(__name__)

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.executescript("""
      CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE,
        password_hash TEXT, salt TEXT, subscribed INTEGER DEFAULT 0);
      CREATE TABLE IF NOT EXISTS tokens(
        token TEXT PRIMARY KEY, user_id INTEGER);
      CREATE TABLE IF NOT EXISTS sessions(
        id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT,
        audio_url TEXT, tags TEXT DEFAULT '');
      CREATE TABLE IF NOT EXISTS favorites(
        user_id INTEGER, session_id INTEGER, PRIMARY KEY(user_id, session_id));
      CREATE TABLE IF NOT EXISTS bookmarks(
        user_id INTEGER, session_id INTEGER, position REAL,
        PRIMARY KEY(user_id, session_id));
      CREATE TABLE IF NOT EXISTS settings(
        user_id INTEGER PRIMARY KEY, data TEXT DEFAULT '{}');
    """)
    con.commit()
    con.close()

def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 100_000).hex()

def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    con = db()
    row = con.execute(
        "SELECT u.* FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.token=?",
        (auth[7:],)).fetchone()
    con.close()
    return row

def need_user():
    u = current_user()
    if u is None:
        return None, (jsonify(error="Please log in"), 401)
    return u, None

def session_row_to_json(r, fav):
    return {
        "id": r["id"], "title": r["title"], "audio_url": r["audio_url"],
        "tags": (r["tags"] or "").split(",") if r["tags"] else [],
        "favorite": bool(fav),
    }

@app.post("/register")
def register():
    j = request.get_json(force=True) or {}
    name, email, pw = (j.get("name") or "").strip(), (j.get("email") or "").strip().lower(), j.get("password") or ""
    if not email or not pw or not name:
        return jsonify(error="Name, email and password are required"), 400
    if len(pw) < 6:
        return jsonify(error="Password must be at least 6 characters"), 400
    salt = os.urandom(16)
    con = db()
    try:
        con.execute("INSERT INTO users(name,email,password_hash,salt) VALUES(?,?,?,?)",
                    (name, email, hash_pw(pw, salt.hex()), salt.hex()))
        con.commit()
    except sqlite3.IntegrityError:
        con.close()
        return jsonify(error="That email is already registered"), 400
    token = secrets.token_hex(32)
    uid = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    con.execute("INSERT INTO tokens(token,user_id) VALUES(?,?)", (token, uid))
    con.commit(); con.close()
    return jsonify(token=token)

@app.post("/login")
def login():
    j = request.get_json(force=True) or {}
    email, pw = (j.get("email") or "").strip().lower(), j.get("password") or ""
    con = db()
    u = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    con.close()
    if not u or u["password_hash"] != hash_pw(pw, u["salt"]):
        return jsonify(error="Email or password is incorrect"), 401
    token = secrets.token_hex(32)
    con = db()
    con.execute("INSERT INTO tokens(token,user_id) VALUES(?,?)", (token, u["id"]))
    con.commit(); con.close()
    return jsonify(token=token)

@app.post("/forgot_password")
def forgot_password():
    # Wire your mail provider here; respond the same regardless so accounts
    # are not enumerable.
    return jsonify(ok=True)

@app.post("/change_password")
def change_password():
    u, err = need_user()
    if err: return err
    j = request.get_json(force=True) or {}
    old, new = j.get("old_password") or "", j.get("new_password") or ""
    if len(new) < 6:
        return jsonify(error="New password must be at least 6 characters"), 400
    con = db()
    row = con.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    if row["password_hash"] != hash_pw(old, row["salt"]):
        con.close(); return jsonify(error="Current password is incorrect"), 400
    salt = os.urandom(16)
    con.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?",
                (hash_pw(new, salt.hex()), salt.hex(), u["id"]))
    con.commit(); con.close()
    return jsonify(ok=True)

@app.get("/sessions")
def sessions():
    u, err = need_user()
    if err: return err
    con = db()
    rows = con.execute("SELECT * FROM sessions WHERE user_id=?", (u["id"],)).fetchall()
    favs = {r["session_id"] for r in con.execute(
        "SELECT session_id FROM favorites WHERE user_id=?", (u["id"],)).fetchall()}
    con.close()
    return jsonify(sessions=[session_row_to_json(r, r["id"] in favs) for r in rows])

@app.get("/favorites")
def favorites():
    u, err = need_user()
    if err: return err
    con = db()
    rows = con.execute(
        "SELECT s.* FROM sessions s JOIN favorites f ON f.session_id=s.id "
        "WHERE f.user_id=?", (u["id"],)).fetchall()
    con.close()
    return jsonify(sessions=[session_row_to_json(r, True) for r in rows])

@app.post("/favorite")
def set_favorite():
    u, err = need_user()
    if err: return err
    j = request.get_json(force=True) or {}
    sid, val = j.get("session_id"), bool(j.get("value"))
    con = db()
    if val:
        con.execute("INSERT OR IGNORE INTO favorites(user_id,session_id) VALUES(?,?)", (u["id"], sid))
    else:
        con.execute("DELETE FROM favorites WHERE user_id=? AND session_id=?", (u["id"], sid))
    con.commit(); con.close()
    return jsonify(ok=True)

@app.post("/bookmark")
def set_bookmark():
    u, err = need_user()
    if err: return err
    j = request.get_json(force=True) or {}
    sid, pos = j.get("session_id"), j.get("position") or 0
    con = db()
    con.execute("INSERT OR REPLACE INTO bookmarks(user_id,session_id,position) VALUES(?,?,?)",
                (u["id"], sid, pos))
    con.commit(); con.close()
    return jsonify(ok=True)

@app.get("/bookmarks")
def bookmarks():
    u, err = need_user()
    if err: return err
    con = db()
    rows = con.execute(
        "SELECT s.*, b.position AS pos FROM sessions s JOIN bookmarks b "
        "ON b.session_id=s.id WHERE b.user_id=?", (u["id"],)).fetchall()
    con.close()
    out = []
    for r in rows:
        d = session_row_to_json(r, False)
        d["bookmark_position"] = r["pos"]
        out.append(d)
    return jsonify(sessions=out)

@app.get("/tags")
def tags():
    u, err = need_user()
    if err: return err
    con = db()
    rows = con.execute("SELECT tags FROM sessions WHERE user_id=?", (u["id"],)).fetchall()
    con.close()
    tags = sorted({t.strip() for r in rows for t in (r["tags"] or "").split(",") if t.strip()})
    return jsonify(tags=tags)

@app.post("/add_session")
def add_session():
    u, err = need_user()
    if err: return err
    j = request.get_json(force=True) or {}
    title, url = (j.get("title") or "").strip(), (j.get("audio_url") or "").strip()
    tag_list = [t.strip() for t in (j.get("tags") or []) if t.strip()]
    if not title or not url:
        return jsonify(error="Title and audio_url are required"), 400
    con = db()
    cur = con.execute(
        "INSERT INTO sessions(user_id,title,audio_url,tags) VALUES(?,?,?,?)",
        (u["id"], title, url, ",".join(tag_list)))
    con.commit(); con.close()
    return jsonify(id=cur.lastrowid)

@app.route("/settings", methods=["GET", "POST"])
def settings():
    u, err = need_user()
    if err: return err
    con = db()
    row = con.execute("SELECT data FROM settings WHERE user_id=?", (u["id"],)).fetchone()
    data = row["data"] if row else "{}"
    if request.method == "POST":
        data = request.get_data(as_text=True) or "{}"
        con.execute("INSERT OR REPLACE INTO settings(user_id,data) VALUES(?,?)", (u["id"], data))
        con.commit()
    con.close()
    return jsonify(user=current_user() is not None, subscribed=bool(u["subscribed"]), data=__import__("json").loads(data))

@app.post("/subscribe")
def subscribe():
    """Marks a user subscribed. Wire your payment gateway's webhook here
    (e.g. Razorpay/Stripe 'payment captured') and flip subscribed=1 only
    after a verified payment."""
    u, err = need_user()
    if err: return err
    con = db()
    con.execute("UPDATE users SET subscribed=1 WHERE id=?", (u["id"],))
    con.commit(); con.close()
    return jsonify(ok=True)

# Create the tables when the module loads (gunicorn never runs __main__).
init_db()


def seed_demo_user():
    """Re-create a demo login on every start. The free-tier disk is wiped on
    each restart, so this keeps a known account working. Configured through
    LECTUREHUB_DEMO_EMAIL / LECTUREHUB_DEMO_PASSWORD / LECTUREHUB_DEMO_NAME."""
    email = (os.environ.get("LECTUREHUB_DEMO_EMAIL") or "").strip().lower()
    pw = os.environ.get("LECTUREHUB_DEMO_PASSWORD") or ""
    name = os.environ.get("LECTUREHUB_DEMO_NAME") or "Demo"
    if not email or len(pw) < 6:
        return
    con = db()
    if con.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone() is None:
        salt = os.urandom(16)
        con.execute("INSERT INTO users(name,email,password_hash,salt) VALUES(?,?,?,?)",
                    (name, email, hash_pw(pw, salt.hex()), salt.hex()))
        con.commit()
    uid = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    seed_demo_sessions(con, uid)
    con.close()


DEMO_SESSIONS = [
    ("Demo Lecture 1 - Introduction",
     "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3", "demo,intro"),
    ("Demo Lecture 2 - Basics",
     "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-2.mp3", "demo"),
    ("Demo Lecture 3 - Practice",
     "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-3.mp3", "demo,practice"),
]


def seed_demo_sessions(con, uid):
    """Give the demo user its sample lectures, but only when it has none.
    Lectures added at runtime live on the same wiped disk as the user, so
    after a restart the list is empty again; this refills it exactly once
    per fresh database and never duplicates rows that already exist."""
    count = con.execute("SELECT COUNT(*) FROM sessions WHERE user_id=?", (uid,)).fetchone()[0]
    if count > 0:
        return
    con.executemany(
        "INSERT INTO sessions(user_id,title,audio_url,tags) VALUES(?,?,?,?)",
        [(uid, title, url, tags) for title, url, tags in DEMO_SESSIONS])
    con.commit()


seed_demo_user()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, threaded=True)
