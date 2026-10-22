# Application Security - Injection Demo

A deliberately vulnerable Flask app for the Week 3 injection class. It is styled
like the NTU Learn portal so the attacks happen in a setting students recognise.

Every demo has a **VULNERABLE / SECURE** toggle in the dark demo bar at the top.
You run the technique in vulnerable mode, flip the toggle, and run it again to show
it fail. The bar also shows the exact SQL query or shell command the server built,
so the audience can watch user input cross from data into logic.

> **Warning:** this app is insecure on purpose. Run it only on your own machine and
> never expose it to a network. The techniques here are for this classroom demo;
> running them against systems you don't own is illegal (e.g. under the Computer
> Misuse Act).

## How to run

Requires Python 3 and Flask.

```bash
git clone https://github.com/joshualsz/Application-Security-Injection-Demo.git
cd Application-Security-Injection-Demo
pip install flask
python app.py
```

Then open **http://127.0.0.1:5001**. No internet access is needed, and all the
data is fake.

For the full live-demo script, talking points, and the exact payloads to paste,
see [DEMO_RUN_SHEET.md](DEMO_RUN_SHEET.md).

## The four injections shown

Each one lives on the page where it would naturally occur in a real portal, and
each contrasts a vulnerable implementation against a secure one.

### 1. SQL injection - authentication bypass
**Where:** the sign-in form.

The login query concatenates the username straight into the SQL string. A crafted
username closes the string literal and comments out the password check, so the
`WHERE` clause always evaluates true and the attacker is logged in as admin with no
valid password. It shows how input treated as logic defeats authentication.
**Fix shown:** parameterised query (bound `?` placeholder), so the input is only
ever a value.

### 2. Blind SQL injection - account enumeration
**Where:** the "Check your account" / password-reset box on the sign-in page.

This endpoint only ever replies "account exists" or "no such account" — no data,
no errors. The demo shows that a single bit of feedback is still a leak: boolean
conditions let you ask the database yes/no questions and recover hidden data one
character at a time, and a time-based variant (making the server pause) extracts
data even when there's no visible difference at all. It makes the point that "no
error shown" is not the same as safe. **Fix shown:** parameterised query removes
the differing responses.

### 3. UNION-based SQL injection - data extraction
**Where:** the "Search your courses" box on the dashboard.

The search glues input into the query, so a `UNION SELECT` staples a second result
set — rows from the users table — onto the course results. The leaked user records
(including plaintext passwords) render right inside the student's own course list.
This is injection as theft rather than just bypass. **Fix shown:** parameterised
query reduces the payload to a harmless search string. (It also motivates next
week: those passwords should have been hashed, not stored in plaintext.)

### 4. OS command injection
**Where:** the "Host lookup" page (linked from the demo bar).

A different engine, same root cause. The host value is concatenated into a shell
command run with `shell=True`, so a shell metacharacter lets a second command run
after the intended one. It shows the jump from database compromise to operating-
system control. **Fix shown:** the command is run as an argument list with no shell,
so the extra input is passed as literal text and never executes.

## Seeded demo data

All fake, used so you know the expected answers during the demo:

| username | password      | role  |
|----------|---------------|-------|
| admin    | S3cr3t_Adm1n! | admin |
| jwong    | password123   | user  |
| siti     | letmein2024   | user  |
| kumar    | hunter2       | user  |

## Files

- `app.py` — the demo app (all four endpoints, both modes, inline templates).
- `DEMO_RUN_SHEET.md` — the live-demo choreography, timings, and payload bank.
- `demo.db` — SQLite database, auto-seeded on startup.
- `static/campus.jpg` — banner image for the portal styling.
