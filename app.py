"""
Application Security - Week 3 Injection Demo
===================================================
A deliberately vulnerable teaching app. Runs locally only.

    pip install flask
    python app.py
    open http://127.0.0.1:5000

Four live demos, each with a VULNERABLE <-> SECURE toggle:
  1. Login            - SQLi auth bypass        ' OR '1'='1 --
  2. Product search   - UNION data extraction   ' UNION SELECT ...
  3. Account lookup   - Blind boolean + time    ' AND '1'='1  /  ' OR SLEEP...
  4. Host lookup      - OS command injection    ; whoami

Each page shows the EXACT query/command the server builds, so the
audience can see input crossing from data into logic.

NOTE: intentionally insecure. Never expose this to a network.
"""

import sqlite3
import subprocess
import time
from flask import Flask, request, render_template_string, g

app = Flask(__name__)
DB = "demo.db"

# ---------------------------------------------------------------------------
# Database: in-file SQLite, seeded with fake data (no real credentials)
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,       -- plaintext on purpose, so UNION dumps are legible
            email TEXT,
            role TEXT
        );
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            category TEXT,
            price REAL
        );
        DROP TABLE IF EXISTS modules;
        CREATE TABLE modules (
            id INTEGER PRIMARY KEY,
            code TEXT,
            title TEXT,
            instructor TEXT
        );

        INSERT INTO users (username, password, email, role) VALUES
            ('admin',   'S3cr3t_Adm1n!',  'admin@shop.sg',   'admin'),
            ('jwong',   'password123',    'jwong@shop.sg',   'user'),
            ('siti',    'letmein2024',    'siti@shop.sg',    'user'),
            ('kumar',   'hunter2',        'kumar@shop.sg',   'user');

        INSERT INTO products (name, category, price) VALUES
            ('Mechanical Keyboard', 'peripherals', 89.00),
            ('USB-C Hub',           'peripherals', 35.50),
            ('27" Monitor',         'displays',    299.00),
            ('Laptop Stand',        'accessories', 45.00),
            ('Webcam 1080p',        'peripherals', 59.90);

        INSERT INTO modules (code, title, instructor) VALUES
            ('26S1-SC2079-LEC', '26S1-SC2079-MULTIDISCIPLINARY DES PROJ', 'Multiple Instructors'),
            ('26S1-SC3010-LEC', '26S1-SC3010-COMPUTER SECURITY',          'Multiple Instructors'),
            ('26S1-SC4013-LEC', '26S1-SC4013-APPLICATION SECURITY',       'Multiple Instructors'),
            ('26S1-SC4016-LEC', '26S1-SC4016-CYBER THREAT INTELLIGENCE',  'CCDS Lim Yi Hao');
        """
    )
    con.commit()
    con.close()


# ---------------------------------------------------------------------------
# Shared page shell
# ---------------------------------------------------------------------------

SHELL = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Injection Demo - Application Security</title>
<style>
  :root { --navy:#1a2a6c; --red:#c8102e; --grey:#f2f4f8; --ink:#1f2733; }
  * { box-sizing: border-box; }
  body { font-family: system-ui, Arial, sans-serif; margin:0; color:var(--ink);
         background:#fff; font-size:18px; }
  header { background:var(--navy); color:#fff; padding:14px 28px; display:flex;
           align-items:center; gap:18px; }
  header h1 { font-size:22px; margin:0; }
  nav { display:flex; gap:6px; flex-wrap:wrap; padding:10px 28px; background:var(--grey);
        border-bottom:3px solid var(--red); }
  nav a { text-decoration:none; color:var(--navy); padding:8px 14px; border-radius:6px;
          font-weight:600; }
  nav a.active { background:var(--navy); color:#fff; }
  main { padding:28px; max-width:1000px; margin:0 auto; }
  h2 { color:var(--navy); margin-top:0; }
  .mode { float:right; font-size:15px; }
  .pill { display:inline-block; padding:4px 12px; border-radius:20px; font-weight:700;
          font-size:14px; }
  .pill.vuln { background:#fde8e8; color:#c8102e; }
  .pill.safe { background:#e6f4ea; color:#137333; }
  .toggle { font-size:15px; }
  .toggle a { font-weight:700; text-decoration:none; }
  form.lab { background:var(--grey); padding:20px; border-radius:10px; margin:16px 0; }
  label { display:block; font-weight:600; margin:10px 0 4px; }
  input[type=text], input[type=password] {
     width:100%; padding:10px; font-size:17px; border:1px solid #c3cad6; border-radius:6px; }
  button { margin-top:14px; background:var(--navy); color:#fff; border:0; padding:11px 20px;
           font-size:17px; border-radius:6px; cursor:pointer; }
  .query { background:#0d1117; color:#7ee787; padding:14px 16px; border-radius:8px;
           font-family:ui-monospace, Menlo, Consolas, monospace; font-size:15px;
           white-space:pre-wrap; word-break:break-word; margin:16px 0; }
  .query .tag { color:#8b949e; }
  .result { border:1px solid #d7dce5; border-radius:8px; padding:14px 18px; margin-top:12px; }
  .result.ok { border-left:6px solid #137333; }
  .result.bad { border-left:6px solid #c8102e; }
  table { border-collapse:collapse; width:100%; margin-top:8px; font-size:16px; }
  th, td { border:1px solid #d7dce5; padding:7px 10px; text-align:left; }
  th { background:var(--navy); color:#fff; }
  .hint { font-size:15px; color:#5a6473; background:#fff7e6; border:1px solid #ffe0a3;
          padding:10px 14px; border-radius:8px; margin-top:12px; }
  code { background:#eef1f6; padding:2px 6px; border-radius:4px; }
  .tiny { font-size:14px; color:#6b7280; }
</style>
</head>
<body>
<header>
  <h1>&#9888; Injection Demo</h1>
  <span class="tiny">Application Security</span>
</header>
<nav>
  <a href="/login?mode={{mode}}"   class="{{'active' if page=='login'  else ''}}">1. Login (SQLi)</a>
  <a href="/search?mode={{mode}}"  class="{{'active' if page=='search' else ''}}">2. Search (UNION)</a>
  <a href="/lookup?mode={{mode}}"  class="{{'active' if page=='lookup' else ''}}">3. Lookup (Blind)</a>
  <a href="/ping?mode={{mode}}"    class="{{'active' if page=='ping'   else ''}}">4. Host (Command)</a>
</nav>
<main>
  <div class="mode">
    <span class="toggle">Mode:
      {% if mode == 'vuln' %}
        <span class="pill vuln">VULNERABLE</span>
        &nbsp;<a href="?mode=safe{{extra}}">flip to secure &#8594;</a>
      {% else %}
        <span class="pill safe">SECURE</span>
        &nbsp;<a href="?mode=vuln{{extra}}">flip to vulnerable &#8594;</a>
      {% endif %}
    </span>
  </div>
  {{ body | safe }}
</main>
</body>
</html>
"""


def page(page, mode, body, extra=""):
    extra = f"&{extra}" if extra else ""
    return render_template_string(
        SHELL, page=page, mode=mode, body=body, extra=extra
    )


def mode_of(req):
    return "safe" if req.args.get("mode") == "safe" else "vuln"


def q(sql):
    return f'<div class="query"><span class="tag"># SQL sent to the database</span>\n{sql}</div>'


# ---------------------------------------------------------------------------
# 1. LOGIN  - auth bypass
# ---------------------------------------------------------------------------

# Accent colour for each course card, keyed by code. Rows that don't match
# (e.g. user records surfaced by a UNION injection) fall back to the leak red.
COURSE_COLORS = {
    "26S1-SC2079-LEC": "#19c3b2",
    "26S1-SC3010-LEC": "#7ed957",
    "26S1-SC4013-LEC": "#c8102e",
    "26S1-SC4016-LEC": "#2d6cdf",
}
LEAK_COLOR = "#c8102e"


def course_rows(db, mode, cq):
    """Run the 'Search your courses' query. Returns (rows, sql, bound).

    rows are (code, title, instructor, color) tuples. This is the UNION-based
    injection demo, themed as course search instead of product search.
    """
    if not cq:
        rows = db.execute(
            "SELECT code, title, instructor FROM modules"
        ).fetchall()
        return _as_cards(rows), None, False

    if mode == "vuln":
        sql = ("SELECT code, title, instructor FROM modules "
               "WHERE code LIKE '%" + cq + "%' OR title LIKE '%" + cq + "%'")
        try:
            rows = db.execute(sql).fetchall()
        except Exception as e:
            return [], sql + f"\n-- DB error: {e}", False
        return _as_cards(rows), sql, False

    sql = ("SELECT code, title, instructor FROM modules "
           "WHERE code LIKE ? OR title LIKE ?"
           f"\n-- bound params: ['%{cq}%', '%{cq}%']")
    rows = db.execute(
        "SELECT code, title, instructor FROM modules WHERE code LIKE ? OR title LIKE ?",
        (f"%{cq}%", f"%{cq}%"),
    ).fetchall()
    return _as_cards(rows), sql, True


def _as_cards(rows):
    out = []
    for r in rows:
        code = r[0]
        out.append((code, r[1], r[2], COURSE_COLORS.get(code, LEAK_COLOR)))
    return out


def account_check(db, mode, acct):
    """Blind-injection demo, themed as a 'does this account exist' lookup
    (the kind of leak a password-reset form has). Checks by username.

    Returns (status, sql, bound, elapsed). status is 'yes'/'no'/None.
    The page reveals only that one bit (plus response time for time-based
    payloads) - never rows or errors - so data must be inferred bit by bit.
    """
    if not acct:
        return None, None, False, 0.0

    start = time.time()
    if mode == "vuln":
        sql = "SELECT id FROM users WHERE username = '" + acct + "'"
        bound = False
        try:
            rows = db.execute(sql).fetchall()
        except Exception:
            rows = []  # blind: swallow the error, reveal nothing
    else:
        sql = ("SELECT id FROM users WHERE username = ?"
               f"\n-- bound param: [{acct!r}]")
        bound = True
        try:
            rows = db.execute("SELECT id FROM users WHERE username = ?", (acct,)).fetchall()
        except Exception:
            rows = []
    elapsed = time.time() - start
    return ("yes" if rows else "no"), sql, bound, elapsed

TODOS = [
    ("Oct", "25", "Source code submission", "Assignment · 26S1-SC2079-MULTIDISC...", "Sun · 10/25/26 · 11:59 PM", False),
    ("Oct", "25", "Video Submission",       "Assignment · 26S1-SC2079-MULTIDISC...", "Sun · 10/25/26 · 11:59 PM", True),
    ("Oct", "28", "Side Quest Submission",  "Assignment · 26S1-SC4016-CYBER THR...", "Wed · 10/28/26 · 11:59 PM", False),
]


# A thin teaching strip pinned to the top of the full-page login / dashboard
# screens, so the realistic look never hides the lesson.
DEMO_BAR = """
<div class="demobar">
  <span class="db-title">&#9888; Injection Demo &middot; Application Security &middot; <b>localhost only</b></span>
  <span class="db-mode">Mode:
    {% if mode == 'vuln' %}
      <span class="pill vuln">VULNERABLE</span>
      <a href="/login?mode=safe">flip to secure &#8594;</a>
    {% else %}
      <span class="pill safe">SECURE</span>
      <a href="/login?mode=vuln">flip to vulnerable &#8594;</a>
    {% endif %}
  </span>
  <span class="db-nav">
    <a href="/search?mode={{mode}}">2. Search</a>
    <a href="/lookup?mode={{mode}}">3. Lookup</a>
    <a href="/ping?mode={{mode}}">4. Host</a>
  </span>
</div>
{% if sql %}
<div class="demosql">
  <span class="tag"># SQL sent to the database</span>
{% if bound %}<br><span class="tag"># (parameterised &mdash; input never becomes code)</span>{% endif %}
<pre>{{ sql }}</pre>
</div>
{% endif %}
"""

DEMO_CSS = """
  :root { --navy:#1a2a6c; --red:#c8102e; --ink:#1f2733; }
  * { box-sizing:border-box; }
  body { font-family:system-ui, Arial, sans-serif; margin:0; color:var(--ink); }
  .pill { display:inline-block; padding:2px 10px; border-radius:20px; font-weight:700; font-size:12px; }
  .pill.vuln { background:#fde8e8; color:#c8102e; }
  .pill.safe { background:#e6f4ea; color:#137333; }
  .demobar { background:#0d1117; color:#c9d1d9; font-size:13px; display:flex;
             align-items:center; gap:18px; flex-wrap:wrap; padding:8px 18px; }
  .demobar a { color:#7ee787; text-decoration:none; font-weight:600; margin-left:8px; }
  .demobar .db-nav { margin-left:auto; }
  .demosql { background:#0d1117; color:#7ee787; padding:6px 18px 12px;
             font-family:ui-monospace, Menlo, Consolas, monospace; font-size:13px; }
  .demosql .tag { color:#8b949e; }
  .demosql pre { white-space:pre-wrap; word-break:break-word; margin:4px 0 0; }
"""

LOGIN_PAGE = """
<!doctype html><html><head><meta charset="utf-8">
<title>Sign in &middot; Learning Portal (Demo)</title>
<style>
""" + DEMO_CSS + """
  .wrap { display:flex; min-height:calc(100vh - 38px); }
  .photo { flex:1.2; background:
     linear-gradient(to top, rgba(0,0,0,.6), rgba(0,0,0,.05) 55%),
     url('/static/campus.jpg') center/cover no-repeat;
     display:flex; align-items:flex-end; padding:48px; color:#fff; }
  .photo h2 { font-size:34px; line-height:1.2; margin:0; text-shadow:0 2px 8px rgba(0,0,0,.4); max-width:420px; }
  .panel { flex:1; display:flex; align-items:center; justify-content:center; padding:40px; background:#fff; }
  .card { width:100%; max-width:420px; }
  .card .badge { display:inline-block; background:#fde8e8; color:#c8102e; font-size:12px;
                 font-weight:700; padding:3px 10px; border-radius:6px; margin-bottom:16px; }
  .card h1 { font-size:30px; margin:0 0 20px; color:#111; }
  .card p.sub { font-weight:600; margin:0 0 14px; }
  .card input { width:100%; padding:11px 12px; font-size:15px; border:1px solid #9aa4b2;
                border-radius:0; margin-bottom:12px; }
  .card button { background:#2f6fd6; color:#fff; border:0; padding:9px 26px; font-size:15px;
                 cursor:pointer; }
  .card ul { font-size:14px; color:#333; line-height:1.9; margin:18px 0 0; padding-left:18px; }
  .err { background:#fde8e8; color:#c8102e; border:1px solid #f3b9b9; padding:10px 12px;
         border-radius:6px; margin-bottom:14px; font-size:14px; }
  .hint { font-size:13px; color:#5a6473; background:#fff7e6; border:1px solid #ffe0a3;
          padding:10px 12px; border-radius:8px; margin-top:20px; }
  code { background:#eef1f6; padding:2px 6px; border-radius:4px;
         font-family:ui-monospace, Menlo, Consolas, monospace; }
  .foot { margin-top:40px; padding-top:14px; border-top:1px solid #e6e8ee;
          font-size:13px; color:#888; }
  .foot a { color:#555; text-decoration:none; }
  @media (max-width:760px){ .photo{display:none;} }
</style></head><body>
""" + DEMO_BAR + """
<div class="wrap">
  <div class="photo"><h2>Nanyang Technological University<br><span style="font-size:18px;font-weight:400">Learning Portal &mdash; Security Demo</span></h2></div>
  <div class="panel"><div class="card">
    <span class="badge">DEMO &mdash; not the real NTU login</span>
    <h1>Sign in</h1>
    <p class="sub">Sign in with your organizational account</p>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <form method="get" action="/login">
      <input type="hidden" name="mode" value="{{mode}}">
      <input type="text" name="username" value="{{username}}" placeholder="username@student.main.ntu.edu.sg" autofocus>
      <input type="text" name="password" value="{{password}}" placeholder="Password">
      <button>Sign in</button>
    </form>
    <p class="sub" style="margin-top:22px">Sign in using your network account e.g</p>
    <ul>
      <li>username@staff.main.ntu.edu.sg</li>
      <li>username@student.main.ntu.edu.sg</li>
      <li>username@assoc.main.ntu.edu.sg</li>
    </ul>
    <div class="hint">
      SQLi auth bypass: username <code>' OR '1'='1' --</code> (any password)
      in VULNERABLE mode. Flip to SECURE and try the same.
    </div>
    <div class="foot">
      <a href="/reset?mode={{mode}}">Reset Password</a>
    </div>
  </div></div>
</div>
</body></html>
"""

RESET_PAGE = """
<!doctype html><html><head><meta charset="utf-8">
<title>Reset Password &middot; Learning Portal (Demo)</title>
<style>
""" + DEMO_CSS + """
  .wrap { display:flex; min-height:calc(100vh - 38px); }
  .photo { flex:1.2; background:
     linear-gradient(to top, rgba(0,0,0,.6), rgba(0,0,0,.05) 55%),
     url('/static/campus.jpg') center/cover no-repeat;
     display:flex; align-items:flex-end; padding:48px; color:#fff; }
  .photo h2 { font-size:34px; line-height:1.2; margin:0; text-shadow:0 2px 8px rgba(0,0,0,.4); max-width:420px; }
  .panel { flex:1; display:flex; align-items:center; justify-content:center; padding:40px; background:#fff; }
  .card { width:100%; max-width:420px; }
  .card .badge { display:inline-block; background:#fde8e8; color:#c8102e; font-size:12px;
                 font-weight:700; padding:3px 10px; border-radius:6px; margin-bottom:16px; }
  .card h1 { font-size:30px; margin:0 0 8px; color:#111; }
  .card p.lede { color:#444; font-size:15px; margin:0 0 18px; }
  .card input { width:100%; padding:11px 12px; font-size:15px; border:1px solid #9aa4b2;
                border-radius:0; margin-bottom:12px; }
  .card button { background:#2f6fd6; color:#fff; border:0; padding:9px 26px; font-size:15px; cursor:pointer; }
  .back { display:inline-block; margin-top:22px; font-size:14px; color:#2f6fd6; text-decoration:none; }
  .ares { padding:10px 12px; border-radius:6px; margin:12px 0; font-size:14px; border:1px solid #d7dce5; }
  .ares.ok { border-left:6px solid #137333; }
  .ares.bad { border-left:6px solid #c8102e; }
  .atiny { font-size:12px; color:#6b7280; margin-top:4px; }
  .hint { font-size:13px; color:#5a6473; background:#fff7e6; border:1px solid #ffe0a3;
          padding:10px 12px; border-radius:8px; margin-top:20px; }
  code { background:#eef1f6; padding:2px 6px; border-radius:4px;
         font-family:ui-monospace, Menlo, Consolas, monospace; }
  @media (max-width:760px){ .photo{display:none;} }
</style></head><body>
""" + DEMO_BAR + """
<div class="wrap">
  <div class="photo"><h2>Nanyang Technological University<br><span style="font-size:18px;font-weight:400">Reset Password &mdash; Security Demo</span></h2></div>
  <div class="panel"><div class="card">
    <span class="badge">DEMO &mdash; not the real NTU login</span>
    <h1>Reset your password</h1>
    <p class="lede">Enter your username and we'll check your account before sending
      a reset link.</p>
    <form method="get" action="/reset">
      <input type="hidden" name="mode" value="{{mode}}">
      <input type="text" name="acct" value="{{acct}}" placeholder="Enter your username" autofocus>
      <button>Continue</button>
    </form>
    {% if astatus %}
    <div class="ares {{ 'ok' if astatus=='yes' else 'bad' }}">
      {% if astatus=='yes' %}&#9989; <b>This account exists.</b> A reset link has been sent.{% else %}&#10060; <b>No such account.</b>{% endif %}
      <div class="atiny">Response time: {{ '%.3f'|format(atime) }}s (watch this for time-based payloads).</div>
    </div>
    {% endif %}
    <div class="hint">
      Blind injection &mdash; this check only says "exists" or "no such account",
      the classic account-enumeration leak on a reset form.<br>
      Boolean: <code>admin' AND '1'='1</code> (exists) vs <code>admin' AND '1'='2</code> (gone).<br>
      Extract the admin password one char at a time &mdash;
      <code>admin' AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='S' --</code>
      &mdash; "exists" confirms it starts with <code>S</code>.<br>
      Time-based (slow reply = condition true):
      <code>admin' AND (SELECT CASE WHEN (1=1) THEN (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x&lt;8000000) SELECT count(*) FROM c) ELSE 0 END) &gt;= 0 --</code>
    </div>
    <a class="back" href="/login?mode={{mode}}">&#8592; Back to sign in</a>
  </div></div>
</div>
</body></html>
"""

COURSES_PAGE = """
<!doctype html><html><head><meta charset="utf-8">
<title>Courses &middot; Learning Portal (Demo)</title>
<style>
""" + DEMO_CSS + """
  body { background:#fff; }
  .flash { background:#e6f4ea; border-left:6px solid #137333; color:#14532d;
           padding:10px 18px; font-size:14px; }
  .topbar { display:flex; align-items:center; gap:24px; padding:18px 28px; border-bottom:1px solid #e6e8ee; }
  .topbar .logo { width:40px; height:40px; border-radius:6px; background:var(--navy); color:#fff;
                  display:flex; align-items:center; justify-content:center; font-weight:800; }
  .topbar h1 { font-size:30px; font-weight:400; margin:0; }
  .topbar .cat { margin-left:auto; color:#444; font-size:15px; }
  .layout { display:flex; }
  .side { width:220px; border-right:1px solid #e6e8ee; padding:14px 0; min-height:70vh; }
  .side .me { display:flex; align-items:center; gap:10px; padding:10px 18px 16px; border-bottom:2px solid #111; }
  .side .me .av { width:34px; height:34px; border-radius:50%; background:#cdd4e0; }
  .side a { display:flex; gap:12px; padding:12px 18px; color:#1f2733; text-decoration:none; font-size:15px; }
  .side a.active { background:#eef1f6; font-weight:700; }
  .side a .ic { width:18px; text-align:center; }
  .center { flex:1; padding:22px 28px; }
  .search { width:100%; padding:12px 14px; font-size:15px; border:1px solid #b9c0cc; border-radius:6px; }
  .controls { display:flex; gap:14px; align-items:center; margin:16px 0; font-size:13px; color:#555; flex-wrap:wrap; }
  .controls .box { border:1px solid #b9c0cc; border-radius:4px; padding:6px 12px; min-width:160px; }
  .count { font-size:14px; color:#333; margin:6px 0 14px; }
  .count .chip { background:#111; color:#fff; border-radius:16px; padding:2px 12px; margin-left:8px; font-size:13px; }
  .chint { font-size:13px; color:#5a6473; background:#fff7e6; border:1px solid #ffe0a3;
           padding:10px 14px; border-radius:8px; margin:4px 0 14px; }
  .chint code { background:#eef1f6; padding:2px 6px; border-radius:4px;
                font-family:ui-monospace, Menlo, Consolas, monospace; }
  .enrol { border:1px solid #e6e8ee; border-radius:8px; padding:18px 20px; margin-top:26px; background:#fafbfd; }
  .enrol h3 { margin:0 0 6px; color:var(--navy); }
  .etiny { font-size:12px; color:#6b7280; margin:6px 0; }
  .ein { padding:10px 12px; font-size:15px; border:1px solid #b9c0cc; border-radius:6px; width:280px; max-width:100%; }
  .ebtn { background:var(--navy); color:#fff; border:0; padding:10px 18px; font-size:15px;
          border-radius:6px; cursor:pointer; margin-left:8px; }
  .eres { border:1px solid #d7dce5; border-radius:8px; padding:12px 16px; margin-top:12px; }
  .eres.ok { border-left:6px solid #137333; }
  .eres.bad { border-left:6px solid #c8102e; }
  .course { border:1px solid #e6e8ee; border-left:6px solid #888; border-radius:4px;
            padding:16px 20px; margin-bottom:16px; }
  .course .code { color:#6b7280; font-size:14px; }
  .course .name { font-weight:700; font-size:18px; margin:4px 0 8px; }
  .course .meta { font-size:14px; color:#2f6fd6; }
  .rail { width:300px; border-left:1px solid #e6e8ee; padding:22px; }
  .rail h3 { margin:0 0 14px; }
  .rail h4 { margin:22px 0 10px; color:#333; }
  .empty { background:#f3f4f7; border-radius:8px; padding:26px; text-align:center; color:#777; font-size:14px; }
  .todo { display:flex; gap:12px; margin-bottom:16px; }
  .todo .cal { border:1px solid #cdd4e0; border-top:3px solid #2f6fd6; border-radius:4px;
               width:46px; text-align:center; font-size:12px; padding:2px 0 4px; }
  .todo .cal b { display:block; font-size:18px; }
  .todo .t { font-weight:700; font-size:14px; }
  .todo .d { font-size:13px; color:#555; }
  .todo .late { font-size:12px; color:#c8102e; }
  @media (max-width:900px){ .rail,.side{display:none;} }
</style></head><body>
""" + DEMO_BAR + """
<div class="flash">&#9989; Authenticated as <b>{{user}}</b> (role: {{role}}) &mdash;
  the query matched {{nrows}} row(s).{% if mode=='vuln' %} Login bypassed via SQL injection.{% endif %}
  &nbsp;<a href="/login?mode={{mode}}" style="color:#137333;font-weight:700">sign out</a></div>
<div class="topbar">
  <div class="logo">NTU</div>
  <h1>Courses</h1>
  <div class="cat">&#128218; Course Catalogue</div>
</div>
<div class="layout">
  <div class="side">
    <div class="me"><div class="av"></div><b>CCDS {{user|upper}}</b></div>
    <a href="#"><span class="ic">&#127963;</span>Institution Page</a>
    <a href="#"><span class="ic">&#127760;</span>Activity</a>
    <a href="#" class="active"><span class="ic">&#128218;</span>Courses</a>
    <a href="#"><span class="ic">&#128101;</span>Communities</a>
    <a href="#"><span class="ic">&#128197;</span>Calendar</a>
    <a href="#"><span class="ic">&#9993;</span>Messages</a>
    <a href="#"><span class="ic">&#128202;</span>Grades</a>
    <a href="#"><span class="ic">&#9999;</span>Resources</a>
    <a href="/login?mode={{mode}}"><span class="ic">&#9211;</span>Sign Out</a>
  </div>
  <div class="center">
    <form method="get" action="/login">
      <input type="hidden" name="mode" value="{{mode}}">
      <input type="hidden" name="username" value="{{login_user}}">
      <input type="hidden" name="password" value="{{login_pass}}">
      <input class="search" name="cq" value="{{cq}}" placeholder="Search your courses" autofocus>
    </form>
    <div class="controls">
      <div class="box"><small>Terms</small><br><b>26S1</b></div>
      <div class="box"><small>Filters</small><br><b>All courses</b></div>
      <div class="box"><b>25</b> items per page</div>
    </div>
    <div class="chint">
      Normal: <code>security</code>. The course list has 3 columns (code, title, instructor).
      Dump credentials with:<br>
      <code>' UNION SELECT username, password, role FROM users --</code><br>
      Leaked accounts appear as red "course" cards.
    </div>
    <div class="count">{{courses|length}} results
      {% if cq %}<span class="chip">search &#10006;</span>{% else %}<span class="chip">26S1 &#10006;</span>{% endif %}</div>
    {% if not courses %}<div class="empty">No courses found.</div>{% endif %}
    {% for code, name, instr, color in courses %}
    <div class="course" style="border-left-color:{{color}}">
      <div class="code">{{code}}</div>
      <div class="name">{{name}}</div>
      <div class="meta">Open &nbsp;|&nbsp; {{instr}} &nbsp;|&nbsp; More info &#9662;</div>
    </div>
    {% endfor %}
  </div>
  <div class="rail">
    <h3>To Do</h3>
    <h4>Overdue</h4>
    <div class="empty">No overdue items in past 7 days</div>
    <h4>Due Today</h4>
    <div class="empty">No items due today</div>
    <h4>Due Soon</h4>
    {% for mon, day, title, sub, when, late in todos %}
    <div class="todo">
      <div class="cal">{{mon}}<b>{{day}}</b></div>
      <div><div class="t">{{title}}</div><div class="d">{{sub}}</div>
        <div class="d">{{when}}</div>
        {% if late %}<div class="late">&#9888; Late submissions not allowed</div>{% endif %}
      </div>
    </div>
    {% endfor %}
  </div>
</div>
</body></html>
"""


@app.route("/reset")
def reset():
    """Password-reset page - the blind-injection demo (account enumeration)."""
    mode = mode_of(request)
    acct = request.args.get("acct", "")
    status, asql, abound, atime = account_check(get_db(), mode, acct)
    return render_template_string(
        RESET_PAGE, mode=mode, acct=_esc(acct),
        sql=asql, bound=abound, astatus=status, atime=atime)


@app.route("/login")
def login():
    mode = mode_of(request)
    u = request.args.get("username", "")
    p = request.args.get("password", "")

    # No submission yet -> show the sign-in screen.
    if not (u or p):
        return render_template_string(LOGIN_PAGE, mode=mode, username="",
                                      password="", error=None, sql=None, bound=False)

    db = get_db()
    if mode == "vuln":
        sql = ("SELECT * FROM users WHERE username = '" + u +
               "' AND password = '" + p + "'")
        bound = False
        try:
            rows = db.execute(sql).fetchall()
        except Exception as e:
            return render_template_string(LOGIN_PAGE, mode=mode, username=_esc(u),
                                          password=_esc(p), error=f"DB error: {e}",
                                          sql=sql, bound=False)
    else:
        sql = ("SELECT * FROM users WHERE username = ? AND password = ?"
               f"\n-- bound params: [{u!r}, {p!r}]")
        bound = True
        rows = db.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                          (u, p)).fetchall()

    if rows:
        cq = request.args.get("cq", "")
        cards, csql, cbound = course_rows(db, mode, cq)
        # When a course search is active, show the UNION query; else the login one.
        shown_sql, shown_bound = (csql, cbound) if cq else (sql, bound)
        return render_template_string(
            COURSES_PAGE, mode=mode, sql=shown_sql, bound=shown_bound,
            user=rows[0]["username"], role=rows[0]["role"], nrows=len(rows),
            courses=cards, todos=TODOS, cq=_esc(cq),
            login_user=u, login_pass=p,
        )
    return render_template_string(
        LOGIN_PAGE, mode=mode, username=_esc(u), password=_esc(p),
        error="Login failed — no matching user.", sql=sql, bound=bound,
    )


# ---------------------------------------------------------------------------
# 2. SEARCH  - UNION extraction
# ---------------------------------------------------------------------------

SEARCH_FORM = """
<h2>2. Product Search &mdash; UNION-Based Data Extraction</h2>
<form class="lab" method="get" action="/search">
  <input type="hidden" name="mode" value="{mode}">
  <label>Search products</label>
  <input type="text" name="term" value="{t}" autofocus>
  <button>Search</button>
</form>
<div class="hint">
  Normal: <code>keyboard</code>. The results table has 4 columns (id, name, category, price).
  Dump credentials with:<br>
  <code>' UNION SELECT id, username, password, role FROM users --</code>
</div>
{query}
{result}
"""


@app.route("/search")
def search():
    mode = mode_of(request)
    t = request.args.get("term", "")
    query_html = ""
    result_html = ""

    if t:
        db = get_db()
        if mode == "vuln":
            sql = ("SELECT id, name, category, price FROM products "
                   "WHERE name LIKE '%" + t + "%'")
            query_html = q(sql)
            try:
                rows = db.execute(sql).fetchall()
            except Exception as e:
                rows = []
                query_html += f'<div class="result bad">DB error: {e}</div>'
        else:
            sql = ("SELECT id, name, category, price FROM products "
                   "WHERE name LIKE ?")
            query_html = q(sql + f"\n<span class='tag'># bound param:</span> ['%{t}%']")
            rows = db.execute(sql, (f"%{t}%",)).fetchall()

        if rows:
            cells = "".join(
                "<tr>" + "".join(f"<td>{_esc(str(c))}</td>" for c in r) + "</tr>"
                for r in rows
            )
            result_html = (
                '<div class="result ok"><b>Results:</b>'
                '<table><tr><th>col 1</th><th>col 2</th><th>col 3</th><th>col 4</th></tr>'
                f'{cells}</table></div>'
            )
        else:
            result_html = '<div class="result bad">No products found.</div>'

    body = SEARCH_FORM.format(mode=mode, t=_esc(t),
                              query=query_html, result=result_html)
    return page("search", mode, body, extra=_qs(term=t))


# ---------------------------------------------------------------------------
# 3. LOOKUP  - blind boolean + time-based
# ---------------------------------------------------------------------------

LOOKUP_FORM = """
<h2>3. Account Lookup &mdash; Blind Injection</h2>
<p class="tiny">This page NEVER shows query results or errors. It only says
"account exists" or "no such account". You infer data from that one bit.</p>
<form class="lab" method="get" action="/lookup">
  <input type="hidden" name="mode" value="{mode}">
  <label>Account ID</label>
  <input type="text" name="id" value="{i}" autofocus>
  <button>Check</button>
</form>
<div class="hint">
  Boolean: <code>1' AND '1'='1</code> (exists) vs <code>1' AND '1'='2</code> (gone).<br>
  Extract: <code>1' AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='S' --</code>
  &mdash; "exists" confirms the admin password starts with S.<br>
  Time-based (slow = condition true): <code>1' AND (SELECT CASE WHEN (1=1) THEN (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x&lt;8000000) SELECT count(*) FROM c) ELSE 0 END) &gt;= 0 --</code>
  &mdash; swap <code>1=1</code> for a real test; watch the response-time line.
</div>
{query}
{result}
"""


@app.route("/lookup")
def lookup():
    mode = mode_of(request)
    i = request.args.get("id", "")
    query_html = ""
    result_html = ""

    if i:
        db = get_db()
        start = time.time()
        if mode == "vuln":
            sql = "SELECT id FROM users WHERE id = '" + i + "'"
            query_html = q(sql)
            try:
                rows = db.execute(sql).fetchall()
            except Exception:
                rows = []  # blind: swallow the error, reveal nothing
        else:
            sql = "SELECT id FROM users WHERE id = ?"
            query_html = q(sql + f"\n<span class='tag'># bound param:</span> [{i!r}]")
            try:
                rows = db.execute(sql, (i,)).fetchall()
            except Exception:
                rows = []
        elapsed = time.time() - start

        if rows:
            result_html = ('<div class="result ok"><b>&#9989; Account exists.</b></div>')
        else:
            result_html = ('<div class="result bad"><b>&#10060; No such account.</b></div>')
        result_html += (f'<p class="tiny">Response time: {elapsed:.3f}s '
                        f'(watch this for time-based payloads).</p>')

    body = LOOKUP_FORM.format(mode=mode, i=_esc(i),
                              query=query_html, result=result_html)
    return page("lookup", mode, body, extra=_qs(id=i))


# ---------------------------------------------------------------------------
# 4. PING  - OS command injection
# ---------------------------------------------------------------------------

PING_FORM = """
<h2>4. Host Lookup &mdash; OS Command Injection</h2>
<p class="tiny">A "diagnostic" tool. The base command is a harmless
<code>echo</code>, so injected commands run but nothing destructive is invited.</p>
<form class="lab" method="get" action="/ping">
  <input type="hidden" name="mode" value="{mode}">
  <label>Hostname</label>
  <input type="text" name="host" value="{h}" autofocus>
  <button>Look up</button>
</form>
<div class="hint">
  Normal: <code>example.com</code>. Inject with:
  <code>example.com; whoami</code> or <code>example.com &amp;&amp; id</code>
  (Windows: <code>example.com &amp; whoami</code>).<br>
  Keep payloads harmless in a live demo &mdash; <code>whoami</code>, <code>id</code>,
  <code>echo PWNED</code>.
</div>
{query}
{result}
"""


@app.route("/ping")
def ping():
    mode = mode_of(request)
    h = request.args.get("host", "")
    query_html = ""
    result_html = ""

    if h:
        if mode == "vuln":
            cmd = 'echo Resolving ' + h
            query_html = (f'<div class="query"><span class="tag"># shell command '
                          f'(shell=True)</span>\n{_esc(cmd)}</div>')
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True,
                                     text=True, timeout=5)
                output = out.stdout + out.stderr
            except Exception as e:
                output = str(e)
        else:
            query_html = ('<div class="query"><span class="tag"># argument list '
                          '(no shell) </span>\n["echo", "Resolving", '
                          f'{h!r}]</div>')
            try:
                out = subprocess.run(["echo", "Resolving", h],
                                     capture_output=True, text=True, timeout=5)
                output = out.stdout + out.stderr
            except Exception as e:
                output = str(e)

        cls = "bad" if mode == "vuln" else "ok"
        result_html = (f'<div class="result {cls}"><b>Command output:</b>'
                       f'<div class="query">{_esc(output.strip())}</div></div>')

    body = PING_FORM.format(mode=mode, h=_esc(h),
                            query=query_html, result=result_html)
    return page("ping", mode, body, extra=_qs(host=h))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _qs(**kw):
    return "&".join(f"{k}={_esc(v)}" for k, v in kw.items() if v)


@app.route("/")
def home():
    return login()


if __name__ == "__main__":
    init_db()
    print("\n  Injection demo running:  http://127.0.0.1:5001\n")
    app.run(debug=False, port=5001)
