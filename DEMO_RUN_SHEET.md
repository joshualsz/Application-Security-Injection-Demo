# Injection Demo - Run Sheet (Application Security Week 3)

A choreography for the live demo. Keep this open on your phone or a second screen.
The app is `app.py`, dressed up to look like the NTU Learn portal so the room sees
the attack in a setting they use every day. Every technique has a VULNERABLE /
SECURE toggle (top-left demo bar) so you show the attack, then flip one switch and
show the same payload failing. That contrast is the whole point.

---

## Before class (2 minutes)

```bash
pip install flask          # once
python app.py              # start it
```

Open `http://127.0.0.1:5001`. You land on the **portal sign-in page**. The thin dark
bar across the top is the teaching strip: it holds the VULNERABLE / SECURE toggle,
links to the Host demo, and shows the exact SQL the server just built.

No internet needed. The data is fake. Pre-type nothing: the audience should watch
you type the payload.

Checklist:
- [ ] Browser zoom at ~150% so the back row can read the SQL strip
- [ ] This run sheet open on your phone
- [ ] Payload bank (bottom of this file) ready to copy if live typing goes wrong
- [ ] Say the ethics line early (see below)

**Ethics line (say it once, up front):** "This is a deliberately broken clone on my
own laptop - not the real NTU Learn. Running these payloads against a system you do
not own is a crime under the Computer Misuse Act. In this module we only touch Juice
Shop and authorised targets."

---

## The arc

You already taught the theory. The demo proves it: input crossing from *data* into
*logic*. The dark strip shows the exact query the server builds, so the room sees the
crossing happen. The three SQL techniques sit where they naturally belong in a real
portal:

1. **Login bypass** - the sign-in form
2. **Blind injection** - the "Check your account" box on the sign-in page
3. **UNION extraction** - the "Search your courses" box on the dashboard

A fourth technique, **OS command injection**, lives on its own Host page (reached from
the demo bar) - a different engine, same disease.

Total live-demo budget: about 12-15 minutes. Leave the rest for the tutorial.

---

## Demo 1 - Login: auth bypass (3 min)

**Page:** the portal sign-in screen (where you start). Mode starts VULNERABLE.

1. Normal login first. Username `admin`, password `wrong`. Click Sign in. The red
   strip shows the query glued your input straight into the string. Result: login
   failed.
2. Now the payload. Username field:
   ```
   ' OR '1'='1' --
   ```
   Password: anything. Click Sign in.
3. Point at the SQL strip. The quote closed the string, `OR '1'='1'` made the WHERE
   always true, `--` commented out the password check. **You are dropped straight
   into the Courses dashboard as admin, with no password.** The green banner names
   who you are and says the login was bypassed.

**Talking point:** "The database did exactly what it was told. The bug is that my
input became part of the sentence, not a value inside it. And notice where it put me:
straight into someone's course portal."

4. **Flip to SECURE** (demo bar, top-left). Go back to `/login` and re-run the *same*
   payload. Strip now shows a `?` placeholder plus a bound parameter. Result: login
   failed.

**Line:** "Same payload, one code change. The input is now a value, never logic."

---

## Demo 2 - Blind injection: account lookup (3-4 min)

**Page:** the sign-in screen again, the **"Forgot your password? Check your account"**
box below the Sign in button. VULNERABLE.

This is the account-enumeration leak that password-reset forms are warned about. It
says only "This account exists" or "No such account" - never data or errors. You
extract data from that single bit. This is the "no error shown" row from your
SQLi-types slide made real.

1. **Boolean, prove the channel.** Username box: `admin' AND '1'='1` -> exists.
   Then `admin' AND '1'='2` -> gone. Same base name, opposite answers. That
   difference is a leak.
2. **Boolean extraction.** Ask the database a yes/no question about data you cannot
   see:
   ```
   admin' AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='S' --
   ```
   "exists" means the admin password starts with S. Try `='A'` -> gone. One
   character at a time, you recover the whole password without ever seeing it.
3. **Time-based.** When there is not even a true/false difference, make the server
   pause. Watch the "Response time" line:
   ```
   admin' AND (SELECT CASE WHEN (1=1) THEN (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<8000000) SELECT count(*) FROM c) ELSE 0 END) >= 0 --
   ```
   Noticeably slower (about half a second here) vs instant. Swap `1=1` for a real test
   like the `substr` check above: slow means true, instant means false. The clock is
   the answer.

**Talking point:** "No feedback is not safety. A password-reset page that says
'account exists' vs 'no such account' already leaks who has an account - and if the
attacker can see any difference at all, even a time delay, the data behind it leaks
too. It is just slower."

*(Note: real MySQL/MSSQL use `SLEEP(5)` or `WAITFOR DELAY`. SQLite has neither, so
this app uses a deliberately expensive query to create the same delay. Mention that
so nobody memorises the SQLite form for an exam.)*

4. **Flip to SECURE** and re-run the boolean payload: the username is treated as a
   literal value, no leak ("No such account").

---

## Demo 3 - Search: UNION data extraction (3 min)

**Page:** the Courses dashboard (log in first, any way you like), the **"Search your
courses"** box. VULNERABLE.

1. Normal search: `security`. Real modules come back (Computer Security, Application
   Security). Note the course list is built from 3 columns (code, title, instructor).
2. The payload. This is injection as *theft*, not just bypass:
   ```
   ' UNION SELECT username, password, role FROM users --
   ```
3. The user table is now stapled onto the course list as **red "course" cards** -
   usernames, **plaintext passwords**, and roles. `admin / S3cr3t_Adm1n! / admin` is
   right there among the modules.

**Talking point:** "Bypass logs one attacker in. UNION hands them the entire user
table, rendered right inside the student's own course list. Same vulnerability, far
worse day for the company. This is the TalkTalk and Heartland story from your
breaches slide."

4. **Flip to SECURE.** Same payload returns "No courses found" - the payload is now
   just a harmless search string.

**Bridge to next week:** those leaked passwords are *plaintext*. Even without the
injection, storing passwords like this is its own finding - they should be hashed.
Good hook into authentication/storage.

---

## Demo 4 - Host lookup: OS command injection (2-3 min)

**Page:** `Host` link in the demo bar (top-left). VULNERABLE. Different engine, same
disease.

1. Normal use: `example.com`. Output: `Resolving example.com`.
2. The payload:
   ```
   example.com; whoami
   ```
   The `;` ends the first command and your second one runs. Output now includes the
   OS user the server runs as.

**Talking point:** "SQLi targets the database. This targets the operating system.
Same root cause: my input was treated as a command, not an argument. This is the
jump from data breach to full server control on your Impact slide, and the shape
behind Log4Shell."

3. **Flip to SECURE.** The command is built as an argument list, no shell. Your
   `; whoami` is printed as literal text. Nothing executes.

Keep injected commands harmless in front of a room: `whoami`, `id`, `echo PWNED`.
Never type anything destructive even as a joke.

---

## Optional: your "Pause & Predict" slide, live

Your deck already has the Payload A `admin' AND '1'='1` vs Payload B `admin' AND
'1'='2` exercise. Run it in the "Check your account" box as a class vote before you
reveal: ask the room to predict which returns "exists" and why, give 60 seconds, then
type both. It lands harder when they committed to an answer first.

---

## If something breaks

- **App will not start / port busy:** another copy is running. `pkill -f app.py`
  then restart. (Port 5001 is used on purpose - macOS AirPlay squats on 5000.) To
  change it, edit `port=5001` at the bottom of `app.py`.
- **Browser shows "Access denied / HTTP 403" on 127.0.0.1:** that is macOS AirPlay
  Receiver on port 5000, not the app. The app is on **5001**.
- **Payload does nothing:** check you are in VULNERABLE mode (red pill in the demo
  bar). SECURE mode blocking it is the demo working, not failing.
- **Live typing fumbles:** copy from the payload bank below. Each page also shows its
  payloads in a yellow hint box.
- **Total failure:** the payloads plus the before/after queries are in this sheet. You
  can walk the concept from the SQL strip on your slides without the app.

---

## Payload bank (copy-paste)

```
# 1. Login auth bypass (sign-in username field) -> lands on dashboard
' OR '1'='1' --

# 2. Blind boolean, exists then gone (Check your account box)
admin' AND '1'='1
admin' AND '1'='2

# 2b. Blind extraction - admin password first char
admin' AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='S' --

# 2c. Time-based (slow = true)
admin' AND (SELECT CASE WHEN (1=1) THEN (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<8000000) SELECT count(*) FROM c) ELSE 0 END) >= 0 --

# 3. UNION dump (Search your courses box) - 3 columns
' UNION SELECT username, password, role FROM users --

# 4. OS command injection (Host page)
example.com; whoami
```

## Seeded data (so you know the answers)

| username | password        | role  |
|----------|-----------------|-------|
| admin    | S3cr3t_Adm1n!   | admin |
| jwong    | password123     | user  |
| siti     | letmein2024     | user  |
| kumar    | hunter2         | user  |

## The one sentence to close on

"Every one of these was the same mistake in a different language: the program let
input become logic. The fix was always the same: keep input as data. Parameterise
everything."
