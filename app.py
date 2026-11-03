"""
CRECITA - Professional Signup Page
Run:
    pip install flask
    python app.py
Open: http://127.0.0.1:5000
"""

import os
import re
import secrets
import sqlite3
from datetime import date, datetime

from flask import Flask, render_template_string, request, session
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crecita_users.db")

COUNTRIES = [
    ("+91", "India"), ("+1", "United States"), ("+1", "Canada"), ("+44", "United Kingdom"),
    ("+61", "Australia"), ("+49", "Germany"), ("+33", "France"), ("+971", "United Arab Emirates"),
    ("+65", "Singapore"), ("+81", "Japan"), ("+86", "China"), ("+55", "Brazil"),
    ("+27", "South Africa"), ("+94", "Sri Lanka"), ("+977", "Nepal"), ("+880", "Bangladesh"),
]
INDUSTRIES = ["Technology", "Finance & Banking", "Healthcare", "Education", "Manufacturing",
              "Retail & E-commerce", "Consulting", "Media & Entertainment", "Other"]
COMPANY_SIZES = ["1-10", "11-50", "51-200", "201-500", "501-1000", "1000+"]
ROLES = ["Founder / CEO", "Manager", "Developer / Engineer", "Designer", "Analyst",
         "Sales / Marketing", "Student", "Other"]


# ----------------------------------------------------------------- database
def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                phone TEXT NOT NULL,
                dob TEXT NOT NULL,
                gender TEXT,
                organization TEXT,
                industry TEXT,
                company_size TEXT,
                job_role TEXT,
                country TEXT NOT NULL,
                city TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                newsletter INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )"""
        )


# --------------------------------------------------------------- validation
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
USER_RE = re.compile(r"^[A-Za-z0-9_]{4,20}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'\-]{0,49}$")


def validate(form):
    errors = {}
    f = {k: form.get(k, "").strip() for k in form}

    if not NAME_RE.match(f.get("first_name", "")):
        errors["first_name"] = "Enter a valid first name."
    if not NAME_RE.match(f.get("last_name", "")):
        errors["last_name"] = "Enter a valid last name."
    if not EMAIL_RE.match(f.get("email", "")):
        errors["email"] = "Enter a valid email address."

    digits = re.sub(r"\D", "", f.get("phone", ""))
    if not 7 <= len(digits) <= 15:
        errors["phone"] = "Enter a valid phone number (7-15 digits)."

    try:
        dob = datetime.strptime(f.get("dob", ""), "%Y-%m-%d").date()
        today = date.today()
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        if age < 18:
            errors["dob"] = "You must be at least 18 years old."
        elif age > 110:
            errors["dob"] = "Enter a valid date of birth."
    except ValueError:
        errors["dob"] = "Select your date of birth."

    if not f.get("country"):
        errors["country"] = "Select your country."
    if len(f.get("city", "")) < 2:
        errors["city"] = "Enter your city."

    if not USER_RE.match(f.get("username", "")):
        errors["username"] = "4-20 characters: letters, numbers, underscore."

    pw = form.get("password", "")
    if (len(pw) < 8 or not re.search(r"[a-z]", pw) or not re.search(r"[A-Z]", pw)
            or not re.search(r"\d", pw) or not re.search(r"[^A-Za-z0-9]", pw)):
        errors["password"] = "Min 8 chars with upper, lower, number and symbol."
    if pw != form.get("confirm_password", ""):
        errors["confirm_password"] = "Passwords do not match."

    if not form.get("terms"):
        errors["terms"] = "You must accept the Terms & Privacy Policy."
    return errors


# ----------------------------------------------------------------- template
PAGE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CRECITA | Create your account</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{
    --bg1:#070b1f; --bg2:#0f1b4d; --bg3:#2a0f4d;
    --accent:#6c7bff; --accent2:#22d3ee; --pink:#c084fc;
    --text:#e8ecff; --muted:#9aa4d6; --card:rgba(255,255,255,.07);
    --border:rgba(255,255,255,.14); --err:#ff6b81; --ok:#34d399;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{
    font-family:'Poppins',system-ui,sans-serif; color:var(--text); min-height:100vh;
    background:linear-gradient(135deg,var(--bg1),var(--bg2) 55%,var(--bg3));
    background-attachment:fixed; display:flex; align-items:center; justify-content:center;
    padding:32px 16px; position:relative; overflow-x:hidden;
  }
  /* ---------- background theme ---------- */
  body::before{ /* subtle grid */
    content:""; position:fixed; inset:0; z-index:0; pointer-events:none;
    background-image:linear-gradient(rgba(255,255,255,.04) 1px,transparent 1px),
                     linear-gradient(90deg,rgba(255,255,255,.04) 1px,transparent 1px);
    background-size:48px 48px;
    mask-image:radial-gradient(ellipse at center,#000 30%,transparent 80%);
  }
  .orb{position:fixed;border-radius:50%;filter:blur(80px);opacity:.55;z-index:0;pointer-events:none;
       animation:float 14s ease-in-out infinite}
  .orb.o1{width:420px;height:420px;background:#4f46e5;top:-120px;left:-100px}
  .orb.o2{width:360px;height:360px;background:#06b6d4;bottom:-120px;right:-80px;animation-delay:-5s}
  .orb.o3{width:280px;height:280px;background:#c026d3;top:40%;left:55%;animation-delay:-9s;opacity:.35}
  @keyframes float{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(40px,-40px) scale(1.12)}}

  /* ---------- layout ---------- */
  .wrapper{position:relative;z-index:1;width:100%;max-width:1120px;display:grid;
           grid-template-columns:1fr 1.45fr;border-radius:28px;overflow:hidden;
           background:var(--card);border:1px solid var(--border);backdrop-filter:blur(22px);
           box-shadow:0 30px 80px rgba(0,0,0,.5)}
  .brand{padding:48px 40px;display:flex;flex-direction:column;justify-content:space-between;
         background:linear-gradient(160deg,rgba(108,123,255,.28),rgba(192,132,252,.12) 60%,transparent)}
  .logo{display:flex;align-items:center;gap:12px;font-weight:700;font-size:26px;letter-spacing:3px}
  .logo .mark{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;font-size:24px;
              background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 8px 24px rgba(108,123,255,.5)}
  .brand h2{font-size:30px;line-height:1.25;margin:36px 0 12px;font-weight:600}
  .brand p{color:var(--muted);font-size:14px;line-height:1.7}
  .features{list-style:none;margin-top:28px;display:grid;gap:16px}
  .features li{display:flex;gap:12px;font-size:14px;color:#cdd5ff;align-items:flex-start}
  .features .ic{flex:0 0 32px;height:32px;border-radius:9px;background:rgba(255,255,255,.1);display:grid;place-items:center}
  .stats{display:flex;gap:24px;margin-top:36px;padding-top:24px;border-top:1px solid var(--border)}
  .stats b{display:block;font-size:22px;color:#fff}
  .stats span{font-size:12px;color:var(--muted)}

  .form-side{padding:44px 44px 36px}
  .form-side h1{font-size:28px;font-weight:600}
  .form-side .sub{color:var(--muted);font-size:14px;margin:6px 0 24px}
  fieldset{border:none;margin-bottom:22px}
  legend{font-size:12px;letter-spacing:1.6px;text-transform:uppercase;color:var(--accent2);
         font-weight:600;margin-bottom:12px;padding:0}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  .full{grid-column:1/-1}
  label{display:block;font-size:12.5px;color:var(--muted);margin-bottom:6px;font-weight:500}
  label i{color:var(--err);font-style:normal}
  input,select{
    width:100%;padding:12px 14px;border-radius:12px;border:1px solid var(--border);
    background:rgba(8,12,35,.55);color:var(--text);font:inherit;font-size:14px;outline:none;transition:.2s}
  input::placeholder{color:#6f78a8}
  select option{background:#10173d;color:#fff}
  input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(108,123,255,.25)}
  .has-err input,.has-err select{border-color:var(--err)}
  .msg{font-size:12px;color:var(--err);margin-top:5px;min-height:0}
  .phone-row{display:grid;grid-template-columns:120px 1fr;gap:8px}
  .pw-wrap{position:relative}
  .pw-wrap button{position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;
                  color:var(--muted);cursor:pointer;font-size:12px;font-family:inherit}
  .meter{height:5px;border-radius:4px;background:rgba(255,255,255,.1);margin-top:8px;overflow:hidden}
  .meter div{height:100%;width:0;border-radius:4px;transition:.3s}
  .meter-label{font-size:11.5px;color:var(--muted);margin-top:4px}
  .radio-row{display:flex;gap:10px;flex-wrap:wrap}
  .radio-row label{display:flex;align-items:center;gap:8px;margin:0;padding:10px 16px;border-radius:12px;
                   border:1px solid var(--border);cursor:pointer;color:var(--text);font-size:13.5px;background:rgba(8,12,35,.4)}
  .radio-row input{width:auto;accent-color:var(--accent)}
  .check{display:flex;gap:10px;align-items:flex-start;font-size:13px;color:#c3cbf5;margin:10px 0;cursor:pointer}
  .check input{width:18px;height:18px;margin-top:2px;accent-color:var(--accent);flex:0 0 auto}
  .check a{color:var(--accent2);text-decoration:none}
  .btn{width:100%;margin-top:14px;padding:15px;border:none;border-radius:14px;font:inherit;font-weight:600;
       font-size:16px;color:#fff;cursor:pointer;letter-spacing:.5px;
       background:linear-gradient(135deg,var(--accent),#8b5cf6 55%,var(--accent2));
       box-shadow:0 12px 30px rgba(108,123,255,.45);transition:.25s}
  .btn:hover{transform:translateY(-2px);box-shadow:0 16px 38px rgba(108,123,255,.6)}
  .login{text-align:center;font-size:13.5px;color:var(--muted);margin-top:18px}
  .login a{color:var(--accent2);text-decoration:none;font-weight:500}
  .alert{background:rgba(255,107,129,.12);border:1px solid rgba(255,107,129,.4);color:#ffb3c0;
         padding:12px 14px;border-radius:12px;font-size:13px;margin-bottom:18px}

  /* ---------- success ---------- */
  .success{grid-column:1/-1;padding:70px 30px;text-align:center}
  .success .tick{width:84px;height:84px;border-radius:50%;margin:0 auto 22px;display:grid;place-items:center;
                 font-size:42px;background:linear-gradient(135deg,var(--ok),var(--accent2));box-shadow:0 12px 34px rgba(52,211,153,.45)}
  .success h1{font-size:30px;margin-bottom:10px}
  .success p{color:var(--muted);max-width:460px;margin:0 auto 26px;line-height:1.7}
  .success a{display:inline-block;padding:13px 30px;border-radius:12px;color:#fff;text-decoration:none;font-weight:600;
             background:linear-gradient(135deg,var(--accent),var(--accent2))}

  @media(max-width:900px){
    .wrapper{grid-template-columns:1fr}
    .brand{padding:32px 28px}.stats{display:none}.form-side{padding:30px 22px}
  }
  @media(max-width:520px){.grid{grid-template-columns:1fr}.phone-row{grid-template-columns:105px 1fr}}
</style>
</head>
<body>
<div class="orb o1"></div><div class="orb o2"></div><div class="orb o3"></div>

<main class="wrapper">
{% if success %}
  <section class="success">
    <div class="tick">✓</div>
    <h1>Welcome to CRECITA, {{ name }}!</h1>
    <p>Your account has been created successfully. We've registered <b>{{ email }}</b>.
       Check your inbox for next steps to get started.</p>
    <a href="/">Back to home</a>
  </section>
{% else %}
  <aside class="brand">
    <div>
      <div class="logo"><span class="mark">C</span>CRECITA</div>
      <h2>Build, grow and scale with CRECITA.</h2>
      <p>Join thousands of professionals and teams who trust CRECITA to power their business growth.</p>
      <ul class="features">
        <li><span class="ic">🔒</span><div><b>Enterprise-grade security</b><br>Passwords are encrypted with industry-standard hashing.</div></li>
        <li><span class="ic">⚡</span><div><b>Get started in minutes</b><br>Simple onboarding with no credit card required.</div></li>
        <li><span class="ic">🌍</span><div><b>Global community</b><br>Collaborate with teams across 40+ countries.</div></li>
        <li><span class="ic">💬</span><div><b>24/7 support</b><br>Our experts are always here to help.</div></li>
      </ul>
    </div>
    <div class="stats">
      <div><b>50K+</b><span>Active users</span></div>
      <div><b>40+</b><span>Countries</span></div>
      <div><b>99.9%</b><span>Uptime</span></div>
    </div>
  </aside>

  <section class="form-side">
    <h1>Create your account</h1>
    <p class="sub">Fill in your details below to join CRECITA.</p>

    {% if errors %}<div class="alert">Please fix the highlighted fields and try again.</div>{% endif %}

    <form method="post" id="signup" novalidate autocomplete="on">
      <input type="hidden" name="csrf_token" value="{{ csrf }}">

      <fieldset>
        <legend>Personal information</legend>
        <div class="grid">
          {% macro field(name, label, type='text', ph='', cls='') %}
            <div class="{{ cls }} {{ 'has-err' if errors.get(name) }}">
              <label for="{{ name }}">{{ label }} <i>*</i></label>
              <input id="{{ name }}" name="{{ name }}" type="{{ type }}" placeholder="{{ ph }}" value="{{ form.get(name,'') }}">
              {% if errors.get(name) %}<div class="msg">{{ errors[name] }}</div>{% endif %}
            </div>
          {% endmacro %}
          {{ field('first_name','First name','text','John') }}
          {{ field('last_name','Last name','text','Doe') }}
          {{ field('email','Email address','email','you@company.com','full') }}

          <div class="full {{ 'has-err' if errors.get('phone') }}">
            <label for="phone">Phone number <i>*</i></label>
            <div class="phone-row">
              <select name="dial" aria-label="Country code">
                {% for code, c in countries %}
                  <option value="{{ code }}" {{ 'selected' if form.get('dial')==code and form.get('dial_c', c)==c or (not form.get('dial') and c=='India') }}>{{ code }} {{ c[:3] }}</option>
                {% endfor %}
              </select>
              <input id="phone" name="phone" type="tel" placeholder="98765 43210" value="{{ form.get('phone','') }}">
            </div>
            {% if errors.get('phone') %}<div class="msg">{{ errors['phone'] }}</div>{% endif %}
          </div>

          {{ field('dob','Date of birth','date','') }}
          <div>
            <label>Gender</label>
            <div class="radio-row">
              {% for g in ['Male','Female','Other'] %}
              <label><input type="radio" name="gender" value="{{ g }}" {{ 'checked' if form.get('gender')==g }}> {{ g }}</label>
              {% endfor %}
            </div>
          </div>
        </div>
      </fieldset>

      <fieldset>
        <legend>Professional details</legend>
        <div class="grid">
          <div class="full">
            <label for="organization">Company / Organization</label>
            <input id="organization" name="organization" placeholder="Your company name" value="{{ form.get('organization','') }}">
          </div>
          <div>
            <label for="job_role">Job role</label>
            <select id="job_role" name="job_role">
              <option value="">Select role</option>
              {% for r in roles %}<option {{ 'selected' if form.get('job_role')==r }}>{{ r }}</option>{% endfor %}
            </select>
          </div>
          <div>
            <label for="industry">Industry</label>
            <select id="industry" name="industry">
              <option value="">Select industry</option>
              {% for i in industries %}<option {{ 'selected' if form.get('industry')==i }}>{{ i }}</option>{% endfor %}
            </select>
          </div>
          <div class="full">
            <label for="company_size">Company size</label>
            <select id="company_size" name="company_size">
              <option value="">Select size</option>
              {% for s in sizes %}<option {{ 'selected' if form.get('company_size')==s }}>{{ s }} employees</option>{% endfor %}
            </select>
          </div>
        </div>
      </fieldset>

      <fieldset>
        <legend>Location</legend>
        <div class="grid">
          <div class="{{ 'has-err' if errors.get('country') }}">
            <label for="country">Country <i>*</i></label>
            <select id="country" name="country">
              <option value="">Select country</option>
              {% for _, c in countries %}<option {{ 'selected' if form.get('country')==c }}>{{ c }}</option>{% endfor %}
            </select>
            {% if errors.get('country') %}<div class="msg">{{ errors['country'] }}</div>{% endif %}
          </div>
          {{ field('city','City','text','Hyderabad') }}
        </div>
      </fieldset>

      <fieldset>
        <legend>Account security</legend>
        <div class="grid">
          {{ field('username','Username','text','john_doe','full') }}
          <div class="{{ 'has-err' if errors.get('password') }}">
            <label for="password">Password <i>*</i></label>
            <div class="pw-wrap">
              <input id="password" name="password" type="password" placeholder="••••••••" autocomplete="new-password">
              <button type="button" data-toggle="password">Show</button>
            </div>
            <div class="meter"><div id="bar"></div></div>
            <div class="meter-label" id="barLabel">Use 8+ chars with upper, lower, number &amp; symbol</div>
            {% if errors.get('password') %}<div class="msg">{{ errors['password'] }}</div>{% endif %}
          </div>
          <div class="{{ 'has-err' if errors.get('confirm_password') }}">
            <label for="confirm_password">Confirm password <i>*</i></label>
            <div class="pw-wrap">
              <input id="confirm_password" name="confirm_password" type="password" placeholder="••••••••" autocomplete="new-password">
              <button type="button" data-toggle="confirm_password">Show</button>
            </div>
            <div class="msg" id="matchMsg" style="min-height:0"></div>
            {% if errors.get('confirm_password') %}<div class="msg">{{ errors['confirm_password'] }}</div>{% endif %}
          </div>
        </div>
      </fieldset>

      <label class="check {{ 'has-err' if errors.get('terms') }}">
        <input type="checkbox" name="terms" {{ 'checked' if form.get('terms') }}>
        <span>I agree to CRECITA's <a href="#">Terms of Service</a> and <a href="#">Privacy Policy</a>. <i style="color:var(--err);font-style:normal">*</i></span>
      </label>
      {% if errors.get('terms') %}<div class="msg">{{ errors['terms'] }}</div>{% endif %}
      <label class="check">
        <input type="checkbox" name="newsletter" {{ 'checked' if form.get('newsletter') }}>
        <span>Send me product updates, tips and offers from CRECITA.</span>
      </label>

      <button class="btn" type="submit">Create Account</button>
      <p class="login">Already have an account? <a href="#">Sign in</a></p>
    </form>
  </section>
{% endif %}
</main>

<script>
  // show / hide password
  document.querySelectorAll('[data-toggle]').forEach(function(btn){
    btn.addEventListener('click', function(){
      var el = document.getElementById(btn.dataset.toggle);
      var show = el.type === 'password';
      el.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Hide' : 'Show';
    });
  });

  // password strength meter
  var pw = document.getElementById('password'), bar = document.getElementById('bar'),
      lbl = document.getElementById('barLabel'), cpw = document.getElementById('confirm_password'),
      mm = document.getElementById('matchMsg');
  if (pw) {
    pw.addEventListener('input', function(){
      var v = pw.value, s = 0;
      if (v.length >= 8) s++;
      if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++;
      if (/\d/.test(v)) s++;
      if (/[^A-Za-z0-9]/.test(v)) s++;
      var names = ['Too weak','Weak','Fair','Good','Strong'];
      var cols  = ['#ff6b81','#ff6b81','#fbbf24','#22d3ee','#34d399'];
      bar.style.width = (v ? Math.max(s,1) * 25 : 0) + '%';
      bar.style.background = cols[s];
      lbl.textContent = v ? 'Password strength: ' + names[s] : 'Use 8+ chars with upper, lower, number & symbol';
      checkMatch();
    });
    cpw.addEventListener('input', checkMatch);
  }
  function checkMatch(){
    if (!cpw.value) { mm.textContent = ''; return; }
    var ok = cpw.value === pw.value;
    mm.style.color = ok ? '#34d399' : '#ff6b81';
    mm.textContent = ok ? 'Passwords match' : 'Passwords do not match';
  }

  // phone: digits and common separators only
  var ph = document.getElementById('phone');
  if (ph) ph.addEventListener('input', function(){ ph.value = ph.value.replace(/[^\d\s\-]/g, ''); });

  // dob limits (18+)
  var dob = document.getElementById('dob');
  if (dob) {
    var t = new Date(); t.setFullYear(t.getFullYear() - 18);
    dob.max = t.toISOString().split('T')[0];
  }
</script>
</body>
</html>
"""


# ------------------------------------------------------------------- routes
@app.route("/", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        session["csrf"] = secrets.token_hex(16)
        return render_template_string(
            PAGE, form={}, errors={}, success=False, csrf=session["csrf"],
            countries=COUNTRIES, industries=INDUSTRIES, sizes=COMPANY_SIZES, roles=ROLES,
        )

    form = request.form
    errors = {}
    if not session.get("csrf") or form.get("csrf_token") != session.get("csrf"):
        errors["csrf"] = "Session expired. Please try again."
    errors.update(validate(form))

    if not errors:
        try:
            with sqlite3.connect(DB_PATH) as db:
                db.execute(
                    """INSERT INTO users (first_name,last_name,email,phone,dob,gender,organization,
                       industry,company_size,job_role,country,city,username,password_hash,newsletter,created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        form["first_name"].strip(), form["last_name"].strip(),
                        form["email"].strip().lower(),
                        f"{form.get('dial', '')} {form['phone'].strip()}",
                        form["dob"], form.get("gender", ""), form.get("organization", "").strip(),
                        form.get("industry", ""), form.get("company_size", ""), form.get("job_role", ""),
                        form["country"], form["city"].strip(), form["username"].strip(),
                        generate_password_hash(form["password"]),
                        1 if form.get("newsletter") else 0,
                        datetime.utcnow().isoformat(timespec="seconds"),
                    ),
                )
            session.pop("csrf", None)
            return render_template_string(
                PAGE, success=True, name=form["first_name"].strip(), email=form["email"].strip().lower(),
                form={}, errors={}, csrf="", countries=COUNTRIES, industries=INDUSTRIES,
                sizes=COMPANY_SIZES, roles=ROLES,
            )
        except sqlite3.IntegrityError as exc:
            msg = str(exc).lower()
            if "email" in msg:
                errors["email"] = "This email is already registered."
            else:
                errors["username"] = "This username is already taken."

    session["csrf"] = secrets.token_hex(16)
    return render_template_string(
        PAGE, form=form, errors=errors, success=False, csrf=session["csrf"],
        countries=COUNTRIES, industries=INDUSTRIES, sizes=COMPANY_SIZES, roles=ROLES,
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
