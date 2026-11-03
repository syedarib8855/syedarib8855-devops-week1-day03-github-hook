"""
CRECITA Employee Portal
-----------------------
Sign Up  ->  Sign In  ->  Company Dashboard (employee directory)

Run:
    pip install flask
    python crecita_portal.py
Open: http://127.0.0.1:5000
"""

import os
import re
import secrets
import sqlite3
from datetime import date, datetime
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crecita_portal.db")

DEPARTMENTS = ["Engineering", "Design", "Marketing", "Sales", "Finance",
               "Human Resources", "Operations", "Customer Support", "Management"]


# ======================================================================
# Database
# ======================================================================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                emp_code TEXT UNIQUE,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                phone TEXT NOT NULL,
                gender TEXT,
                department TEXT NOT NULL,
                designation TEXT NOT NULL,
                joining_date TEXT NOT NULL,
                city TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )


# ======================================================================
# Security helpers (CSRF + login guard)
# ======================================================================
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def verify_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or expired form. Please go back and try again.")


@app.context_processor
def inject_globals():
    return {"csrf_token": csrf_token, "year": date.today().year}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "uid" not in session:
            flash("Please sign in to access the dashboard.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ======================================================================
# Validation
# ======================================================================
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'\-]{1,59}$")


def validate_signup(form):
    e = {}
    if not NAME_RE.match(form.get("full_name", "").strip()):
        e["full_name"] = "Enter your full name (letters only)."
    if not EMAIL_RE.match(form.get("email", "").strip()):
        e["email"] = "Enter a valid email address."
    digits = re.sub(r"\D", "", form.get("phone", ""))
    if not 10 <= len(digits) <= 15:
        e["phone"] = "Enter a valid phone number (10-15 digits)."
    if form.get("department") not in DEPARTMENTS:
        e["department"] = "Select your department."
    if len(form.get("designation", "").strip()) < 2:
        e["designation"] = "Enter your job title."
    try:
        jd = datetime.strptime(form.get("joining_date", ""), "%Y-%m-%d").date()
        if jd > date.today():
            e["joining_date"] = "Joining date cannot be in the future."
    except ValueError:
        e["joining_date"] = "Select your joining date."
    if len(form.get("city", "").strip()) < 2:
        e["city"] = "Enter your city."

    pw = form.get("password", "")
    if (len(pw) < 8 or not re.search(r"[a-z]", pw) or not re.search(r"[A-Z]", pw)
            or not re.search(r"\d", pw) or not re.search(r"[^A-Za-z0-9]", pw)):
        e["password"] = "Min 8 chars with upper, lower, number and symbol."
    if pw != form.get("confirm_password", ""):
        e["confirm_password"] = "Passwords do not match."
    if not form.get("terms"):
        e["terms"] = "Please accept the company policy."
    return e


# ======================================================================
# Routes
# ======================================================================
@app.route("/")
def home():
    return redirect(url_for("dashboard") if "uid" in session else url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "uid" in session:
        return redirect(url_for("dashboard"))
    form, errors = {}, {}
    if request.method == "POST":
        form = request.form
        errors = validate_signup(form)
        if not errors:
            db = get_db()
            try:
                cur = db.execute(
                    """INSERT INTO employees
                       (full_name,email,phone,gender,department,designation,joining_date,city,
                        password_hash,created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        form["full_name"].strip().title(), form["email"].strip().lower(),
                        form["phone"].strip(), form.get("gender", ""), form["department"],
                        form["designation"].strip(), form["joining_date"], form["city"].strip().title(),
                        generate_password_hash(form["password"]),
                        datetime.now().isoformat(timespec="seconds"),
                    ),
                )
                db.execute("UPDATE employees SET emp_code=? WHERE id=?",
                           (f"CRC-{cur.lastrowid:04d}", cur.lastrowid))
                db.commit()
            except sqlite3.IntegrityError:
                errors["email"] = "This email is already registered."
            else:
                flash("Account created successfully! Please sign in to continue.", "success")
                return redirect(url_for("login"))
    return render_template("signup.html", form=form, errors=errors, departments=DEPARTMENTS)


@app.route("/login", methods=["GET", "POST"])
def login():
    if "uid" in session:
        return redirect(url_for("dashboard"))
    ident = ""
    if request.method == "POST":
        ident = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM employees WHERE email = ? OR emp_code = ?",
            (ident.lower(), ident.upper()),
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["uid"] = user["id"]
            session["csrf"] = secrets.token_hex(16)
            return redirect(url_for("dashboard"))
        flash("Invalid email / employee ID or password.", "error")
    return render_template("login.html", ident=ident)


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    me = db.execute("SELECT * FROM employees WHERE id = ?", (session["uid"],)).fetchone()
    if me is None:  # account removed
        session.clear()
        return redirect(url_for("login"))

    employees = db.execute(
        """SELECT emp_code, full_name, email, phone, department, designation,
                  joining_date, city, id FROM employees ORDER BY id DESC"""
    ).fetchall()

    month_prefix = date.today().strftime("%Y-%m")
    new_this_month = sum(1 for r in employees if r["joining_date"].startswith(month_prefix))
    dept_counts = {}
    for r in employees:
        dept_counts[r["department"]] = dept_counts.get(r["department"], 0) + 1
    dept_rows = sorted(dept_counts.items(), key=lambda x: -x[1])
    top = dept_rows[0][1] if dept_rows else 1

    return render_template(
        "dashboard.html", me=me, employees=employees, total=len(employees),
        dept_count=len(dept_counts), new_this_month=new_this_month,
        dept_rows=dept_rows, top=top, departments=sorted(dept_counts),
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


# ======================================================================
# Templates (kept inside this file so it stays a single-file project)
# ======================================================================
BASE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{% block title %}CRECITA{% endblock %}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --bg:#f4f6fb; --white:#fff;
  --p:#4f46e5; --p2:#7c3aed; --teal:#14b8a6; --amber:#f59e0b; --rose:#f43f5e; --green:#10b981;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Plus Jakarta Sans',system-ui,sans-serif;color:var(--ink);background:var(--bg);min-height:100vh}
a{color:var(--p);text-decoration:none;font-weight:600}
.flash{padding:12px 16px;border-radius:12px;font-size:14px;font-weight:500;margin-bottom:16px}
.flash.success{background:#ecfdf5;color:#047857;border:1px solid #a7f3d0}
.flash.error{background:#fff1f2;color:#be123c;border:1px solid #fecdd3}
.logo{display:flex;align-items:center;gap:10px;font-weight:800;font-size:22px;letter-spacing:2px}
.logo .mk{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;color:#fff;font-size:20px;
          background:linear-gradient(135deg,var(--p),var(--p2));box-shadow:0 8px 20px rgba(79,70,229,.35)}

/* ---------- AUTH PAGES ---------- */
.auth-bg{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:28px 16px;position:relative;overflow:hidden;
  background:
   radial-gradient(900px 500px at 12% 8%,rgba(124,58,237,.30),transparent 60%),
   radial-gradient(800px 500px at 92% 90%,rgba(20,184,166,.28),transparent 60%),
   radial-gradient(600px 400px at 85% 10%,rgba(245,158,11,.20),transparent 60%),
   linear-gradient(180deg,#eef2ff,#f8fafc)}
.shape{position:absolute;border-radius:28px;opacity:.5;animation:drift 16s ease-in-out infinite}
.s1{width:130px;height:130px;border:3px solid rgba(79,70,229,.35);top:9%;left:7%;transform:rotate(20deg)}
.s2{width:90px;height:90px;background:rgba(20,184,166,.28);bottom:12%;left:14%;border-radius:50%;animation-delay:-4s}
.s3{width:160px;height:160px;border:3px dashed rgba(124,58,237,.35);bottom:8%;right:8%;border-radius:50%;animation-delay:-8s}
.s4{width:70px;height:70px;background:rgba(245,158,11,.35);top:14%;right:12%;transform:rotate(35deg);animation-delay:-2s}
@keyframes drift{0%,100%{translate:0 0}50%{translate:0 -26px}}
.dots{position:absolute;inset:0;background-image:radial-gradient(rgba(79,70,229,.18) 1.2px,transparent 1.2px);
      background-size:26px 26px;mask-image:radial-gradient(circle at center,#000 20%,transparent 75%);pointer-events:none}

.auth-card{position:relative;z-index:2;width:100%;background:#fff;border-radius:26px;overflow:hidden;
  box-shadow:0 30px 70px rgba(30,27,75,.18);display:grid;grid-template-columns:1fr 1.2fr}
.auth-card.narrow{max-width:960px}.auth-card.wide{max-width:1080px}
.side{padding:44px 38px;color:#fff;position:relative;display:flex;flex-direction:column;justify-content:space-between;
  background:linear-gradient(155deg,#4338ca,#7c3aed 55%,#0ea5a5)}
.side::after{content:"";position:absolute;width:300px;height:300px;border-radius:50%;right:-110px;bottom:-110px;background:rgba(255,255,255,.1)}
.side .logo .mk{background:#fff;color:var(--p)}
.side h2{font-size:30px;line-height:1.25;margin:34px 0 12px;font-weight:800}
.side p{opacity:.85;font-size:14px;line-height:1.7}
.side ul{list-style:none;margin-top:26px;display:grid;gap:14px;position:relative;z-index:1}
.side li{display:flex;gap:10px;font-size:14px;align-items:center}
.side li span{width:26px;height:26px;border-radius:50%;background:rgba(255,255,255,.2);display:grid;place-items:center;font-size:13px;flex:0 0 26px}
.main{padding:40px 42px}
.main h1{font-size:28px;font-weight:800}
.main .sub{color:var(--muted);font-size:14px;margin:6px 0 22px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.full{grid-column:1/-1}
label.l{display:block;font-size:12.5px;font-weight:600;color:#334155;margin-bottom:6px}
label.l i{color:var(--rose);font-style:normal}
.in{width:100%;padding:12px 14px;border:1.5px solid var(--line);border-radius:12px;font:inherit;font-size:14px;background:#f8fafc;color:var(--ink);outline:none;transition:.18s}
.in:focus{border-color:var(--p);background:#fff;box-shadow:0 0 0 4px rgba(79,70,229,.12)}
.err .in{border-color:var(--rose);background:#fff7f8}
.msg{color:var(--rose);font-size:12px;margin-top:5px}
.pw{position:relative}.pw button{position:absolute;right:10px;top:50%;transform:translateY(-50%);border:none;background:none;color:var(--muted);font:inherit;font-size:12px;font-weight:600;cursor:pointer}
.meter{height:5px;background:var(--line);border-radius:4px;margin-top:8px;overflow:hidden}.meter div{height:100%;width:0;transition:.3s}
.hint{font-size:11.5px;color:var(--muted);margin-top:4px}
.radios{display:flex;gap:8px;flex-wrap:wrap}
.radios label{display:flex;align-items:center;gap:6px;padding:10px 14px;border:1.5px solid var(--line);border-radius:12px;font-size:13.5px;cursor:pointer;background:#f8fafc}
.radios input{accent-color:var(--p)}
.check{display:flex;gap:10px;font-size:13px;color:#475569;margin:16px 0 4px;align-items:flex-start}
.check input{width:17px;height:17px;margin-top:2px;accent-color:var(--p)}
.btn{width:100%;margin-top:16px;padding:14px;border:none;border-radius:13px;font:inherit;font-weight:700;font-size:15px;color:#fff;cursor:pointer;
     background:linear-gradient(135deg,var(--p),var(--p2));box-shadow:0 12px 26px rgba(79,70,229,.35);transition:.2s}
.btn:hover{transform:translateY(-2px);box-shadow:0 16px 32px rgba(79,70,229,.45)}
.alt{text-align:center;font-size:14px;color:var(--muted);margin-top:18px}
.sec{font-size:11.5px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--p);margin:6px 0 10px}

/* ---------- DASHBOARD ---------- */
.app{display:grid;grid-template-columns:260px 1fr;min-height:100vh}
.sidebar{background:linear-gradient(180deg,#1e1b4b,#312e81);color:#e0e7ff;padding:26px 20px;display:flex;flex-direction:column;position:sticky;top:0;height:100vh}
.sidebar .logo{color:#fff;margin-bottom:34px}.sidebar .logo .mk{background:#fff;color:var(--p)}
.nav a{display:flex;gap:12px;align-items:center;padding:12px 14px;border-radius:12px;color:#c7d2fe;font-weight:600;font-size:14px;margin-bottom:6px}
.nav a.on{background:rgba(255,255,255,.14);color:#fff}
.me-box{margin-top:auto;background:rgba(255,255,255,.08);border-radius:16px;padding:16px}
.me-box b{display:block;color:#fff;font-size:14px}.me-box span{font-size:12px;color:#a5b4fc}
.me-box button{margin-top:12px;width:100%;padding:10px;border:none;border-radius:10px;background:rgba(255,255,255,.16);color:#fff;font:inherit;font-weight:600;cursor:pointer}
.me-box button:hover{background:var(--rose)}
.content{padding:30px 34px;min-width:0}
.top{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:24px}
.top h1{font-size:26px;font-weight:800}.top p{color:var(--muted);font-size:14px;margin-top:2px}
.badge{background:#fff;border:1px solid var(--line);padding:9px 14px;border-radius:12px;font-size:13px;font-weight:600;color:#475569}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:22px}
.card{background:#fff;border-radius:18px;padding:20px;border:1px solid var(--line);box-shadow:0 4px 14px rgba(15,23,42,.04)}
.card .ic{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;font-size:20px;margin-bottom:12px}
.card b{font-size:28px;font-weight:800;display:block}.card span{font-size:13px;color:var(--muted);font-weight:500}
.row{display:grid;grid-template-columns:1.6fr 1fr;gap:16px;margin-bottom:22px}
.panel{background:#fff;border-radius:18px;padding:22px;border:1px solid var(--line);box-shadow:0 4px 14px rgba(15,23,42,.04)}
.panel h3{font-size:16px;font-weight:700;margin-bottom:14px}
.bar-row{margin-bottom:12px}.bar-row div.t{display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px;font-weight:500}
.bar{height:8px;background:#eef2ff;border-radius:6px;overflow:hidden}.bar i{display:block;height:100%;border-radius:6px;background:linear-gradient(90deg,var(--p),var(--teal))}
.profile{display:flex;gap:14px;align-items:center;margin-bottom:14px}
.av{width:54px;height:54px;border-radius:16px;display:grid;place-items:center;color:#fff;font-weight:800;font-size:20px;background:linear-gradient(135deg,var(--p),var(--p2));flex:0 0 auto}
.kv{display:grid;grid-template-columns:auto 1fr;gap:8px 14px;font-size:13.5px}.kv span{color:var(--muted)}.kv b{font-weight:600;word-break:break-word}
.tools{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.tools .in{max-width:300px;background:#fff}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:14px}
table{width:100%;border-collapse:collapse;font-size:13.5px;min-width:860px}
th{background:#f8fafc;text-align:left;padding:13px 16px;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted)}
td{padding:13px 16px;border-top:1px solid var(--line);vertical-align:middle}
tr:hover td{background:#fafaff}
.who{display:flex;gap:10px;align-items:center}.who .av{width:36px;height:36px;border-radius:11px;font-size:14px}
.who small{display:block;color:var(--muted);font-size:12px}
.tag{display:inline-block;padding:4px 10px;border-radius:20px;background:#eef2ff;color:#4338ca;font-size:12px;font-weight:600}
.you{background:#dcfce7;color:#166534;font-size:11px;padding:2px 8px;border-radius:12px;margin-left:6px;font-weight:700}
.empty{text-align:center;color:var(--muted);padding:30px;display:none}

@media(max-width:960px){
  .auth-card{grid-template-columns:1fr}.side{padding:28px}.main{padding:28px 22px}
  .app{grid-template-columns:1fr}.sidebar{position:static;height:auto}.me-box{margin-top:20px}
  .cards{grid-template-columns:1fr 1fr}.row{grid-template-columns:1fr}.content{padding:22px 16px}
}
@media(max-width:520px){.grid{grid-template-columns:1fr}.cards{grid-template-columns:1fr}}
</style>
</head>
<body>
{% block body %}{% endblock %}
</body>
</html>
"""

SIGNUP = r"""
{% extends "base.html" %}
{% block title %}CRECITA | Create Account{% endblock %}
{% macro field(name, label, type='text', ph='', cls='') %}
  <div class="{{ cls }} {{ 'err' if errors.get(name) }}">
    <label class="l" for="{{ name }}">{{ label }} <i>*</i></label>
    <input class="in" id="{{ name }}" name="{{ name }}" type="{{ type }}" placeholder="{{ ph }}" value="{{ form.get(name,'') }}">
    {% if errors.get(name) %}<div class="msg">{{ errors[name] }}</div>{% endif %}
  </div>
{% endmacro %}
{% block body %}
<div class="auth-bg">
  <div class="dots"></div>
  <div class="shape s1"></div><div class="shape s2"></div><div class="shape s3"></div><div class="shape s4"></div>

  <div class="auth-card wide">
    <aside class="side">
      <div style="position:relative;z-index:1">
        <div class="logo"><span class="mk">C</span>CRECITA</div>
        <h2>Join the CRECITA team workspace</h2>
        <p>Create your employee account to access the company dashboard and connect with your colleagues.</p>
        <ul>
          <li><span>✓</span> Employee ID generated instantly</li>
          <li><span>✓</span> Company-wide employee directory</li>
          <li><span>✓</span> Secure, encrypted credentials</li>
          <li><span>✓</span> Department insights &amp; analytics</li>
        </ul>
      </div>
      <p style="position:relative;z-index:1;font-size:12px;opacity:.7">© {{ year }} CRECITA. All rights reserved.</p>
    </aside>

    <section class="main">
      <h1>Create your account</h1>
      <p class="sub">Enter your employee details to get started.</p>

      <form method="post" novalidate>
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

        <div class="sec">Personal details</div>
        <div class="grid">
          {{ field('full_name','Full name','text','Rahul Sharma','full') }}
          {{ field('email','Work email','email','rahul@crecita.com') }}
          {{ field('phone','Phone number','tel','98765 43210') }}
          <div class="full">
            <label class="l">Gender</label>
            <div class="radios">
              {% for g in ['Male','Female','Other'] %}
              <label><input type="radio" name="gender" value="{{ g }}" {{ 'checked' if form.get('gender')==g }}> {{ g }}</label>
              {% endfor %}
            </div>
          </div>
        </div>

        <div class="sec" style="margin-top:20px">Work details</div>
        <div class="grid">
          <div class="{{ 'err' if errors.get('department') }}">
            <label class="l" for="department">Department <i>*</i></label>
            <select class="in" id="department" name="department">
              <option value="">Select department</option>
              {% for d in departments %}<option {{ 'selected' if form.get('department')==d }}>{{ d }}</option>{% endfor %}
            </select>
            {% if errors.get('department') %}<div class="msg">{{ errors['department'] }}</div>{% endif %}
          </div>
          {{ field('designation','Designation / Job title','text','Software Engineer') }}
          {{ field('joining_date','Joining date','date') }}
          {{ field('city','City','text','Hyderabad') }}
        </div>

        <div class="sec" style="margin-top:20px">Security</div>
        <div class="grid">
          <div class="{{ 'err' if errors.get('password') }}">
            <label class="l" for="password">Password <i>*</i></label>
            <div class="pw">
              <input class="in" id="password" name="password" type="password" placeholder="••••••••" autocomplete="new-password">
              <button type="button" data-t="password">Show</button>
            </div>
            <div class="meter"><div id="bar"></div></div>
            <div class="hint" id="hint">8+ chars, upper, lower, number &amp; symbol</div>
            {% if errors.get('password') %}<div class="msg">{{ errors['password'] }}</div>{% endif %}
          </div>
          <div class="{{ 'err' if errors.get('confirm_password') }}">
            <label class="l" for="confirm_password">Confirm password <i>*</i></label>
            <div class="pw">
              <input class="in" id="confirm_password" name="confirm_password" type="password" placeholder="••••••••" autocomplete="new-password">
              <button type="button" data-t="confirm_password">Show</button>
            </div>
            <div class="hint" id="match"></div>
            {% if errors.get('confirm_password') %}<div class="msg">{{ errors['confirm_password'] }}</div>{% endif %}
          </div>
        </div>

        <label class="check">
          <input type="checkbox" name="terms" {{ 'checked' if form.get('terms') }}>
          <span>I agree to the CRECITA company policy and privacy terms.</span>
        </label>
        {% if errors.get('terms') %}<div class="msg">{{ errors['terms'] }}</div>{% endif %}

        <button class="btn" type="submit">Create Account</button>
        <p class="alt">Already have an account? <a href="{{ url_for('login') }}">Sign in</a></p>
      </form>
    </section>
  </div>
</div>

<script>
document.querySelectorAll('[data-t]').forEach(function(b){
  b.addEventListener('click',function(){
    var el=document.getElementById(b.dataset.t), s=el.type==='password';
    el.type=s?'text':'password'; b.textContent=s?'Hide':'Show';
  });
});
var pw=document.getElementById('password'),cp=document.getElementById('confirm_password'),
    bar=document.getElementById('bar'),hint=document.getElementById('hint'),mt=document.getElementById('match');
pw.addEventListener('input',function(){
  var v=pw.value,s=0;
  if(v.length>=8)s++; if(/[a-z]/.test(v)&&/[A-Z]/.test(v))s++; if(/\d/.test(v))s++; if(/[^A-Za-z0-9]/.test(v))s++;
  var n=['Too weak','Weak','Fair','Good','Strong'],c=['#f43f5e','#f43f5e','#f59e0b','#14b8a6','#10b981'];
  bar.style.width=(v?Math.max(s,1)*25:0)+'%'; bar.style.background=c[s];
  hint.textContent=v?'Strength: '+n[s]:'8+ chars, upper, lower, number & symbol'; chk();
});
cp.addEventListener('input',chk);
function chk(){
  if(!cp.value){mt.textContent='';return;}
  var ok=cp.value===pw.value; mt.style.color=ok?'#10b981':'#f43f5e';
  mt.textContent=ok?'Passwords match':'Passwords do not match';
}
var jd=document.getElementById('joining_date'); if(jd) jd.max=new Date().toISOString().split('T')[0];
</script>
{% endblock %}
"""

LOGIN = r"""
{% extends "base.html" %}
{% block title %}CRECITA | Sign In{% endblock %}
{% block body %}
<div class="auth-bg">
  <div class="dots"></div>
  <div class="shape s1"></div><div class="shape s2"></div><div class="shape s3"></div><div class="shape s4"></div>

  <div class="auth-card narrow">
    <aside class="side">
      <div style="position:relative;z-index:1">
        <div class="logo"><span class="mk">C</span>CRECITA</div>
        <h2>Welcome back to your workspace</h2>
        <p>Sign in to open the company dashboard and view your team's employee details.</p>
        <ul>
          <li><span>✓</span> Live employee directory</li>
          <li><span>✓</span> Department overview</li>
          <li><span>✓</span> Your profile at a glance</li>
        </ul>
      </div>
      <p style="position:relative;z-index:1;font-size:12px;opacity:.7">© {{ year }} CRECITA. All rights reserved.</p>
    </aside>

    <section class="main" style="display:flex;flex-direction:column;justify-content:center">
      <h1>Sign in</h1>
      <p class="sub">Use your work email or employee ID (e.g. CRC-0001).</p>

      {% with msgs = get_flashed_messages(with_categories=true) %}
        {% for cat, m in msgs %}<div class="flash {{ cat }}">{{ m }}</div>{% endfor %}
      {% endwith %}

      <form method="post" novalidate>
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div style="margin-bottom:14px">
          <label class="l" for="identifier">Email or Employee ID</label>
          <input class="in" id="identifier" name="identifier" placeholder="rahul@crecita.com" value="{{ ident }}" required autofocus>
        </div>
        <div>
          <label class="l" for="password">Password</label>
          <div class="pw">
            <input class="in" id="password" name="password" type="password" placeholder="••••••••" required>
            <button type="button" id="tg">Show</button>
          </div>
        </div>
        <button class="btn" type="submit">Sign In to Dashboard</button>
        <p class="alt">New to CRECITA? <a href="{{ url_for('signup') }}">Create an account</a></p>
      </form>
    </section>
  </div>
</div>
<script>
var p=document.getElementById('password'),t=document.getElementById('tg');
t.addEventListener('click',function(){var s=p.type==='password';p.type=s?'text':'password';t.textContent=s?'Hide':'Show';});
</script>
{% endblock %}
"""

DASHBOARD = r"""
{% extends "base.html" %}
{% block title %}CRECITA | Company Dashboard{% endblock %}
{% block body %}
<div class="app">
  <aside class="sidebar">
    <div class="logo"><span class="mk">C</span>CRECITA</div>
    <nav class="nav">
      <a class="on" href="{{ url_for('dashboard') }}">📊 Dashboard</a>
      <a href="#directory">👥 Employees</a>
      <a href="#departments">🏢 Departments</a>
      <a href="#profile">🙍 My Profile</a>
    </nav>
    <div class="me-box">
      <b>{{ me['full_name'] }}</b>
      <span>{{ me['emp_code'] }} · {{ me['designation'] }}</span>
      <form method="post" action="{{ url_for('logout') }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button type="submit">Sign out</button>
      </form>
    </div>
  </aside>

  <main class="content">
    <div class="top">
      <div>
        <h1>Welcome, {{ me['full_name'].split()[0] }} 👋</h1>
        <p>Here is the CRECITA company overview and employee details.</p>
      </div>
      <div class="badge">📅 {{ me['joining_date'] and 'Joined ' ~ me['joining_date'] }}</div>
    </div>

    {% with msgs = get_flashed_messages(with_categories=true) %}
      {% for cat, m in msgs %}<div class="flash {{ cat }}">{{ m }}</div>{% endfor %}
    {% endwith %}

    <section class="cards">
      <div class="card"><div class="ic" style="background:#eef2ff">👥</div><b>{{ total }}</b><span>Total employees</span></div>
      <div class="card"><div class="ic" style="background:#ecfdf5">🏢</div><b>{{ dept_count }}</b><span>Active departments</span></div>
      <div class="card"><div class="ic" style="background:#fff7ed">🆕</div><b>{{ new_this_month }}</b><span>Joined this month</span></div>
      <div class="card"><div class="ic" style="background:#fdf2f8">🆔</div><b>{{ me['emp_code'] }}</b><span>Your employee ID</span></div>
    </section>

    <section class="row">
      <div class="panel" id="departments">
        <h3>Employees by department</h3>
        {% for name, n in dept_rows %}
          <div class="bar-row">
            <div class="t"><span>{{ name }}</span><span>{{ n }}</span></div>
            <div class="bar"><i style="width: {{ (n / top * 100)|round|int }}%"></i></div>
          </div>
        {% endfor %}
      </div>

      <div class="panel" id="profile">
        <h3>My profile</h3>
        <div class="profile">
          <div class="av">{{ me['full_name'][0] }}</div>
          <div><b>{{ me['full_name'] }}</b><br><span class="tag">{{ me['department'] }}</span></div>
        </div>
        <div class="kv">
          <span>Emp ID</span><b>{{ me['emp_code'] }}</b>
          <span>Email</span><b>{{ me['email'] }}</b>
          <span>Phone</span><b>{{ me['phone'] }}</b>
          <span>Title</span><b>{{ me['designation'] }}</b>
          <span>City</span><b>{{ me['city'] }}</b>
        </div>
      </div>
    </section>

    <section class="panel" id="directory">
      <h3>Employee details <span style="color:var(--muted);font-weight:500">({{ total }} registered)</span></h3>
      <div class="tools">
        <input class="in" id="q" placeholder="🔍 Search name, email, ID, city…">
        <select class="in" id="dept" style="max-width:220px;background:#fff">
          <option value="">All departments</option>
          {% for d in departments %}<option>{{ d }}</option>{% endfor %}
        </select>
      </div>

      <div class="tablewrap">
        <table id="tbl">
          <thead>
            <tr><th>Employee</th><th>Emp ID</th><th>Phone</th><th>Department</th><th>Designation</th><th>City</th><th>Joined</th></tr>
          </thead>
          <tbody>
            {% for e in employees %}
            <tr data-dept="{{ e['department'] }}">
              <td>
                <div class="who">
                  <div class="av">{{ e['full_name'][0] }}</div>
                  <div>
                    <b>{{ e['full_name'] }}</b>{% if e['id'] == me['id'] %}<span class="you">YOU</span>{% endif %}
                    <small>{{ e['email'] }}</small>
                  </div>
                </div>
              </td>
              <td>{{ e['emp_code'] }}</td>
              <td>{{ e['phone'] }}</td>
              <td><span class="tag">{{ e['department'] }}</span></td>
              <td>{{ e['designation'] }}</td>
              <td>{{ e['city'] }}</td>
              <td>{{ e['joining_date'] }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
        <div class="empty" id="empty">No employees match your search.</div>
      </div>
    </section>
  </main>
</div>

<script>
var q=document.getElementById('q'),d=document.getElementById('dept'),
    rows=document.querySelectorAll('#tbl tbody tr'),empty=document.getElementById('empty');
function filter(){
  var t=q.value.toLowerCase(),dp=d.value,shown=0;
  rows.forEach(function(r){
    var ok=r.textContent.toLowerCase().indexOf(t)>-1&&(!dp||r.dataset.dept===dp);
    r.style.display=ok?'':'none'; if(ok)shown++;
  });
  empty.style.display=shown?'none':'block';
}
q.addEventListener('input',filter); d.addEventListener('change',filter);
</script>
{% endblock %}
"""

app.jinja_env.loader = DictLoader({
    "base.html": BASE,
    "signup.html": SIGNUP,
    "login.html": LOGIN,
    "dashboard.html": DASHBOARD,
})


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
