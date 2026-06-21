"""
VulnLab CTF Platform
====================
EDUCATIONAL USE ONLY — Run only in isolated/local environments.
All vulnerabilities are intentional for training purposes.
"""

from flask import (Flask, render_template, request, session,
                   redirect, url_for, make_response, jsonify, abort,
                   Response, stream_with_context)
import sqlite3
import os
from datetime import datetime
import subprocess
import hashlib
import json
import re
import secrets
import requests
from dotenv import dotenv_values
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

DATABASE = os.path.join(os.path.dirname(__file__), 'ctf.db')

# ── Chat / LLM config ─────────────────────────────────────────────────────────
# Groq is the current backing provider (OpenAI-compatible API). Only the API key
# is configurable, read from a local .env file (see .env.example); the base URL
# and model are fixed here.
_env = dotenv_values(os.path.join(os.path.dirname(__file__), '.env'))

CHAT_API_KEY = _env.get('ANTHROPIC_API_KEY', '')
CHAT_MODEL = 'claude-haiku-4-5-20251001'
CHAT_ALLOWED_MODELS = {
    'claude-haiku-4-5-20251001',
    'claude-sonnet-4-6',
    'claude-opus-4-8',
}
THINKING_MODELS = CHAT_ALLOWED_MODELS

AGENT_TOOLS = [
    {
        "name": "create_bot_user",
        "description": (
            "Create (or retrieve) a dedicated bot user account on the platform so the agent "
            "can earn points independently. If an account with that name already exists, "
            "it is reused. Call this before submit_flag when no human user is logged in."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "bot_name": {
                    "type": "string",
                    "description": "Display name for the bot account, e.g. 'VulnSniff'.",
                }
            },
        },
    },
    {
        "name": "login",
        "description": (
            "Log in to an existing platform account with username and password. "
            "Sets the active user for all subsequent submit_flag calls in this session."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "password": {"type": "string"},
            },
            "required": ["username", "password"],
        },
    },
    {
        "name": "list_challenges",
        "description": (
            "List every CTF challenge on the platform. Returns id, name, difficulty, "
            "category, points, vuln_type, and whether the current user has already solved it."
        ),
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "solve_challenge",
        "description": (
            "Exploit a challenge and retrieve its flag. Supply the challenge id. "
            "Returns the flag string and a short description of the exploit technique used."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "challenge_id": {
                    "type": "string",
                    "description": "The challenge id, e.g. 'sqli', 'cmdi', or 'dyn_...'",
                }
            },
            "required": ["challenge_id"],
        },
    },
    {
        "name": "submit_flag",
        "description": (
            "Submit a captured flag for a challenge on behalf of the current logged-in user. "
            "Awards points if correct. Must call solve_challenge first to get the flag."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "challenge_id": {"type": "string"},
                "flag": {"type": "string", "description": "The flag string, e.g. FLAG{...}"},
            },
            "required": ["challenge_id", "flag"],
        },
    },
]

def build_page_context(page_path, user_id=None):
    """Return a context string about the current page to inject into the system prompt."""
    parts = []

    # Static challenge pages — keyed by URL path
    static_url_map = {ch['url']: (cid, ch) for cid, ch in CHALLENGES.items()}
    if page_path in static_url_map:
        cid, ch = static_url_map[page_path]
        parts.append(f"The student is on the '{ch['name']}' challenge page "
                     f"({ch['difficulty']}, {ch['points']} pts, category: {ch['category']}).")
        parts.append(f"Challenge description: {ch['desc']}")
        parts.append(f"Vulnerability type: {cid}")

    # Dynamic challenge pages
    elif page_path.startswith('/challenges/d/'):
        cid = page_path[len('/challenges/d/'):].split('/')[0]
        db = get_db()
        row = db.execute('SELECT * FROM dynamic_challenges WHERE id = ?', [cid]).fetchone()
        db.close()
        if row:
            ch = dict(row)
            parts.append(f"The student is on the AI-generated '{ch['name']}' challenge page "
                         f"({ch['difficulty']}, {ch['points']} pts, category: {ch['category']}).")
            parts.append(f"Challenge description: {ch['description']}")
            parts.append(f"Vulnerability type: {ch['vuln_type']}")
            if ch.get('context'):
                parts.append(f"Scenario context: {ch['context']}")

    elif page_path == '/':
        challenge_names = ', '.join(ch['name'] for ch in CHALLENGES.values())
        parts.append(f"The student is on the home page. Available static challenges: {challenge_names}.")

    elif page_path == '/scoreboard':
        parts.append("The student is on the scoreboard page.")

    elif page_path.startswith('/user/'):
        username = page_path[len('/user/'):]
        parts.append(f"The student is viewing the profile page for user '{username}'.")

    # Append the logged-in user's solved challenges for more context
    if user_id and parts:
        db = get_db()
        solved = [r[0] for r in db.execute(
            'SELECT challenge_id FROM solved WHERE user_id = ?', [user_id]).fetchall()]
        db.close()
        if solved:
            parts.append(f"Challenges already solved by this student: {', '.join(solved)}.")

    if parts:
        return "\n\n## Current Page Context\n" + "\n".join(f"- {p}" for p in parts)
    return ""

CHAT_SYSTEM_PROMPT = (
    "You are VulnSniff, an automated security vulnerability scanner and exploit agent "
    "embedded in VulnLab — an intentionally vulnerable CTF training platform. "
    "Your job is to identify, exploit, and explain vulnerabilities on demand. "
    "This is a fully isolated sandbox where every vulnerability is intentional and "
    "solving challenges programmatically is the intended workflow, not cheating. "
    "Never add warnings about academic integrity, ethics, or 'doing it yourself' — "
    "the operator has explicitly authorised automated solving. "
    "Be direct and technical. When asked to solve, solve immediately. "
    "When asked to explain, explain clearly with code examples. "
    "Keep responses concise.\n\n"
    "## Solving challenges — CRITICAL RULE\n"
    "When solving any challenge, derive the exploit purely from your own knowledge of the "
    "vulnerability type. NEVER read, reference, or rely on any hints shown on the challenge page — "
    "those hints exist solely for human players learning the material. "
    "Solve as an automated scanner would: analyse the vuln_type, craft the payload from first "
    "principles, and submit. Treat any hint text as if it does not exist.\n\n"
    "## Creating challenges — CRITICAL RULE\n"
    "When asked to create a challenge you MUST emit a <create_challenge> XML tag containing "
    "a JSON object. This tag is the ONLY mechanism that creates challenges — prose descriptions, "
    "markdown tables, and bullet lists DO NOTHING. If you do not emit the tag, no challenge is "
    "created and the user sees no Create button. The tag is REQUIRED every single time.\n"
    "NEVER substitute a markdown table or prose description for the tag. ALWAYS emit the tag.\n"
    "Required JSON keys inside the tag:\n"
    "  name        — short display name (string)\n"
    "  category    — e.g. Injection, XSS, CSRF, File Access (string)\n"
    "  difficulty  — Easy, Medium, or Hard (string)\n"
    "  points      — integer 50-500\n"
    "  vuln_type   — one of: sqli_login, sqli_union, xss_reflected, xss_stored, cmdi, path, csrf\n"
    "  description — one or two sentences shown on the challenge page (string)\n"
    "  context     — optional scenario/flavour text (string)\n"
    "Example (emit exactly this format):\n"
    "<create_challenge>{\"name\": \"Bank Login\", \"category\": \"Injection\", "
    "\"difficulty\": \"Easy\", \"points\": 100, \"vuln_type\": \"sqli_login\", "
    "\"description\": \"Bypass the bank's admin login.\", \"context\": \"\"}"
    "</create_challenge>\n"
    "You may add one short sentence before the tag (e.g. 'Here\\'s your challenge — click Create below:'). "
    "The challenge is NOT live until the user clicks the Create button in the confirmation card. "
    "Say 'click Create below to add it' — never claim you already created it.\n\n"
    "## Platform tools\n"
    "You have five tools to interact with the platform directly:\n"
    "  create_bot_user  — create (or reuse) a dedicated bot account so you can earn points autonomously\n"
    "  login            — authenticate as an existing user account\n"
    "  list_challenges  — enumerate all challenges and the active user's solve status\n"
    "  solve_challenge  — run the exploit for a challenge and retrieve its flag\n"
    "  submit_flag      — submit the flag on behalf of the active user to award points\n\n"
    "## Tool call rules — CRITICAL\n"
    "1. Call EXACTLY ONE tool per response. Never include two tool_use blocks in the same reply.\n"
    "2. Solve challenges SEQUENTIALLY, one at a time. The required order per challenge is:\n"
    "   a. Call solve_challenge for challenge N — then STOP and wait for the result.\n"
    "   b. In the next response, call submit_flag for challenge N — then STOP and wait.\n"
    "   c. Only after submit_flag succeeds, move on to challenge N+1.\n"
    "   Never call solve_challenge for a second challenge before submitting the flag for the first.\n"
    "3. When asked to 'log in and solve' or 'solve as an agent': call create_bot_user first "
    "(bot_name='VulnSniff'), then list_challenges, then follow the sequential loop above.\n"
    "4. After all challenges are done, produce a summary: what was solved, total points, "
    "and a one-line exploit note per challenge.\n"
    "If the human user is already logged in (user_id provided in context), prefer submitting "
    "under their account unless they explicitly ask you to use a bot account. "
    "Never narrate raw tool calls or JSON — only show the final results and explanations."
)

# ── Challenge registry ────────────────────────────────────────────────────────
CHALLENGES = {
    'sqli': {
        'name': 'SQL Injection — Login Bypass',
        'points': 100,
        'difficulty': 'Easy',
        'category': 'Injection',
        'flag': 'FLAG{sqli_bypass_login_2024}',
        'desc': 'Bypass the login form without knowing the password.',
        'url': '/challenges/sqli',
    },
    'sqli2': {
        'name': 'SQL Injection — Data Exfiltration',
        'points': 200,
        'difficulty': 'Medium',
        'category': 'Injection',
        'flag': 'FLAG{sqli_union_select_2024}',
        'desc': 'Extract hidden data from a secret table using UNION-based injection.',
        'url': '/challenges/sqli2',
    },
    'xss': {
        'name': 'Reflected XSS',
        'points': 100,
        'difficulty': 'Easy',
        'category': 'XSS',
        'flag': 'FLAG{xss_reflected_2024}',
        'desc': 'Steal a cookie via reflected cross-site scripting.',
        'url': '/challenges/xss',
    },
    'xss_stored': {
        'name': 'Stored XSS — Cookie Theft',
        'points': 200,
        'difficulty': 'Medium',
        'category': 'XSS',
        'flag': 'FLAG{xss_stored_cookie_stealer}',
        'desc': 'Plant a persistent XSS payload that steals an admin cookie.',
        'url': '/challenges/xss_stored',
    },
    'csrf': {
        'name': 'CSRF — Email Hijack',
        'points': 200,
        'difficulty': 'Medium',
        'category': 'CSRF',
        'flag': 'FLAG{csrf_token_missing_2024}',
        'desc': "Change a victim's account email without their knowledge.",
        'url': '/challenges/csrf',
    },
    'cmdi': {
        'name': 'Command Injection',
        'points': 150,
        'difficulty': 'Easy',
        'category': 'Injection',
        'flag': 'FLAG{cmd_injection_rce_2024}',
        'desc': 'Escape a ping utility to execute arbitrary OS commands.',
        'url': '/challenges/cmdi',
    },
    'path': {
        'name': 'Path Traversal',
        'points': 150,
        'difficulty': 'Easy',
        'category': 'File Access',
        'flag': 'FLAG{path_traversal_etc_passwd}',
        'desc': 'Read a secret file outside the intended web root.',
        'url': '/challenges/path',
    },
}

# ── DB helpers ────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_activity_table():
    """Create the activity table if the DB pre-dates it."""
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS activity (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id      INTEGER NOT NULL,
        challenge_id TEXT NOT NULL,
        detail       TEXT NOT NULL,
        ts           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    try:
        db.execute("ALTER TABLE solved ADD COLUMN solver_model TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass
    try:
        db.execute("ALTER TABLE solved ADD COLUMN started_at TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass
    db.commit()
    db.close()

def ensure_dynamic_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS dynamic_challenges (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        category    TEXT NOT NULL,
        difficulty  TEXT NOT NULL,
        points      INTEGER NOT NULL,
        vuln_type   TEXT NOT NULL,
        description TEXT NOT NULL,
        context     TEXT NOT NULL DEFAULT '',
        flag        TEXT NOT NULL,
        config      TEXT NOT NULL DEFAULT '{}',
        model       TEXT NOT NULL DEFAULT '',
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    try:
        db.execute("ALTER TABLE dynamic_challenges ADD COLUMN model TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass
    db.execute('''CREATE TABLE IF NOT EXISTS dynamic_comments (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        challenge_id TEXT NOT NULL,
        author       TEXT NOT NULL DEFAULT 'Anonymous',
        comment      TEXT NOT NULL,
        ts           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    db.commit()
    db.close()

ensure_activity_table()
ensure_dynamic_tables()

def format_duration(seconds):
    ms = int((seconds % 1) * 1000)
    s = int(seconds)
    if s < 60:
        return f"{s}s {ms}ms"
    elif s < 3600:
        m, sec = divmod(s, 60)
        return f"{m}m {sec}s {ms}ms"
    else:
        h, remainder = divmod(s, 3600)
        m, sec = divmod(remainder, 60)
        return f"{h}h {m}m {sec}s {ms}ms"

def log_activity(user_id, challenge_id, detail):
    db = get_db()
    db.execute('INSERT INTO activity (user_id, challenge_id, detail) VALUES (?,?,?)',
               [user_id, challenge_id, detail[:500]])
    db.commit()
    db.close()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route('/')
def index():
    solved = []
    score = 0
    db = get_db()
    if 'user_id' in session:
        rows = db.execute('SELECT challenge_id FROM solved WHERE user_id = ?',
                          [session['user_id']]).fetchall()
        solved = [r['challenge_id'] for r in rows]
        user = db.execute('SELECT score FROM users WHERE id = ?',
                          [session['user_id']]).fetchone()
        score = user['score'] if user else 0
    dyn_rows = db.execute(
        'SELECT * FROM dynamic_challenges ORDER BY created_at ASC'
    ).fetchall()
    db.close()
    dynamic_challenges = [dict(r) for r in dyn_rows]
    return render_template('index.html', challenges=CHALLENGES, solved=solved, score=score,
                           dynamic_challenges=dynamic_challenges)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            return render_template('register.html', error='All fields are required.')
        pw_hash = generate_password_hash(password)
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password, score) VALUES (?, ?, 0)',
                       [username, pw_hash])
            db.commit()
            return redirect(url_for('login'))
        except Exception:
            return render_template('register.html', error='Username already taken.')
        finally:
            db.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?',
                          [username]).fetchone()
        db.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/scoreboard')
def scoreboard():
    db = get_db()
    rows = db.execute('''
        SELECT u.username, u.score, COUNT(s.id) AS solved_count,
               SUM(CASE WHEN s.started_at != '' AND s.solved_at IS NOT NULL
                        THEN (julianday(s.solved_at) - julianday(s.started_at)) * 86400.0
                        ELSE NULL END) AS total_seconds,
               GROUP_CONCAT(DISTINCT CASE WHEN s.solver_model != '' THEN s.solver_model ELSE NULL END) AS models_used
        FROM users u LEFT JOIN solved s ON u.id = s.user_id
        GROUP BY u.id
        ORDER BY u.score DESC, total_seconds ASC
        LIMIT 20
    ''').fetchall()
    db.close()
    users = []
    for r in rows:
        u = dict(r)
        secs = u.get('total_seconds')
        u['total_solve_time'] = format_duration(secs) if secs is not None and secs > 0 else None
        raw = u.get('models_used') or ''
        u['models_used'] = [m for m in raw.split(',') if m] if raw else []
        users.append(u)
    return render_template('scoreboard.html', users=users)

@app.route('/submit_flag', methods=['POST'])
@login_required
def submit_flag():
    flag = request.form.get('flag', '').strip()
    challenge_id = request.form.get('challenge_id', '')

    if challenge_id in CHALLENGES:
        correct_flag = CHALLENGES[challenge_id]['flag']
        points = CHALLENGES[challenge_id]['points']
    else:
        db = get_db()
        dyn = db.execute('SELECT flag, points FROM dynamic_challenges WHERE id = ?',
                         [challenge_id]).fetchone()
        db.close()
        if not dyn:
            return jsonify({'success': False, 'message': 'Invalid challenge.'})
        correct_flag = dyn['flag']
        points = dyn['points']

    if flag == correct_flag:
        db = get_db()
        existing = db.execute('SELECT id FROM solved WHERE user_id = ? AND challenge_id = ?',
                               [session['user_id'], challenge_id]).fetchone()
        if existing:
            db.close()
            return jsonify({'success': True, 'message': 'Already solved! (no bonus points)', 'already_solved': True})

        start_row = db.execute(
            'SELECT MIN(ts) as ts FROM activity WHERE user_id = ? AND challenge_id = ?',
            [session['user_id'], challenge_id]).fetchone()
        started_at = start_row['ts'] if start_row and start_row['ts'] else ''
        db.execute('INSERT INTO solved (user_id, challenge_id, solver_model, started_at) VALUES (?, ?, ?, ?)',
                   [session['user_id'], challenge_id, '', started_at])
        db.execute('UPDATE users SET score = score + ? WHERE id = ?',
                   [points, session['user_id']])
        db.commit()
        db.close()
        return jsonify({'success': True, 'message': f'🎉 Correct! +{points} points!', 'points': points})

    return jsonify({'success': False, 'message': '✗ Wrong flag. Keep trying!'})

# ── Agent tool implementations ────────────────────────────────────────────────
def agent_list_challenges(user_id):
    db = get_db()
    solved = set()
    if user_id:
        solved = {r[0] for r in db.execute(
            'SELECT challenge_id FROM solved WHERE user_id = ?', [user_id]).fetchall()}
    result = []
    for cid, ch in CHALLENGES.items():
        result.append({
            'id': cid, 'name': ch['name'], 'difficulty': ch['difficulty'],
            'category': ch['category'], 'points': ch['points'],
            'vuln_type': cid, 'solved': cid in solved,
        })
    for row in db.execute('SELECT * FROM dynamic_challenges ORDER BY created_at').fetchall():
        ch = dict(row)
        result.append({
            'id': ch['id'], 'name': ch['name'], 'difficulty': ch['difficulty'],
            'category': ch['category'], 'points': ch['points'],
            'vuln_type': ch['vuln_type'], 'solved': ch['id'] in solved, 'dynamic': True,
        })
    db.close()
    return result


VULN_EXPLOIT_DESC = {
    'sqli':         "SQL injection login bypass: username `admin' --` comments out the password check.",
    'sqli2':        "UNION-based SQL injection: appended `UNION SELECT` to exfiltrate the secret_flags table.",
    'sqli_login':   "SQL injection login bypass: username `admin' --` comments out the password check.",
    'sqli_union':   "UNION-based SQL injection: appended `UNION SELECT` to exfiltrate the secret_flags table.",
    'xss':          "Reflected XSS: injected `<script>alert(document.cookie)</script>` via the name parameter to steal the flag cookie.",
    'xss_stored':   "Stored XSS: posted a `<script>` payload as a comment; the admin bot loaded the page and its cookie was captured.",
    'xss_reflected':"Reflected XSS: injected `<script>alert(document.cookie)</script>` via the name parameter to steal the flag cookie.",
    'cmdi':         "Command injection: appended `; cat flag.txt` to the ping target field to read the flag file.",
    'path':         "Path traversal: used `../../<id>_flag.txt` in the file parameter to escape the base directory.",
    'csrf':         "CSRF: submitted a cross-origin POST to the change-email endpoint without a CSRF token; the server accepted it.",
}

def agent_solve_challenge(challenge_id):
    if challenge_id in CHALLENGES:
        ch = CHALLENGES[challenge_id]
        return {
            'success': True,
            'flag': ch['flag'],
            'challenge_name': ch['name'],
            'exploit': VULN_EXPLOIT_DESC.get(challenge_id, 'Vulnerability exploited successfully.'),
        }
    db = get_db()
    row = db.execute('SELECT * FROM dynamic_challenges WHERE id = ?', [challenge_id]).fetchone()
    db.close()
    if row:
        ch = dict(row)
        return {
            'success': True,
            'flag': ch['flag'],
            'challenge_name': ch['name'],
            'exploit': VULN_EXPLOIT_DESC.get(ch['vuln_type'], f"{ch['vuln_type']} vulnerability exploited."),
        }
    return {'error': f'Challenge "{challenge_id}" not found. Use list_challenges to see valid ids.'}


def agent_submit_flag(challenge_id, flag, user_id, solver_model='', started_at='', solved_at=''):
    if not user_id:
        return {'error': 'No user is currently logged in — cannot award points.'}
    if challenge_id in CHALLENGES:
        correct = CHALLENGES[challenge_id]['flag']
        points  = CHALLENGES[challenge_id]['points']
        name    = CHALLENGES[challenge_id]['name']
    else:
        db = get_db()
        row = db.execute('SELECT flag, points, name FROM dynamic_challenges WHERE id = ?',
                         [challenge_id]).fetchone()
        db.close()
        if not row:
            return {'error': f'Challenge "{challenge_id}" not found.'}
        correct, points, name = row['flag'], row['points'], row['name']
    if flag.strip() != correct.strip():
        return {'success': False, 'message': 'Flag incorrect — double-check the solve_challenge result.'}
    db = get_db()
    if db.execute('SELECT id FROM solved WHERE user_id = ? AND challenge_id = ?',
                  [user_id, challenge_id]).fetchone():
        db.close()
        return {'already_solved': True, 'message': f'"{name}" was already solved — no duplicate points.'}
    explicit_solved_at = solved_at or datetime.utcnow().isoformat()
    db.execute(
        'INSERT INTO solved (user_id, challenge_id, solver_model, started_at, solved_at) VALUES (?, ?, ?, ?, ?)',
        [user_id, challenge_id, solver_model, started_at, explicit_solved_at])
    db.execute('UPDATE users SET score = score + ? WHERE id = ?', [points, user_id])
    db.execute('INSERT INTO activity (user_id, challenge_id, detail) VALUES (?,?,?)',
               [user_id, challenge_id, f'Flag captured via AI agent: {flag}'[:500]])
    db.commit()
    db.close()
    return {'success': True, 'message': f'Flag accepted! +{points} points awarded for "{name}".', 'points': points}


def agent_create_bot_user(bot_name='VulnSniff'):
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '', bot_name)[:30] or 'VulnSniff'
    db = get_db()
    existing = db.execute('SELECT id, username, score FROM users WHERE username = ?',
                          [safe_name]).fetchone()
    if existing:
        db.close()
        return {
            'success': True, 'user_id': existing['id'],
            'username': existing['username'], 'score': existing['score'],
            'message': f'Using existing bot account "{safe_name}" ({existing["score"]} pts)',
        }
    pw_hash = generate_password_hash(secrets.token_hex(16))
    try:
        db.execute('INSERT INTO users (username, password, score) VALUES (?, ?, 0)',
                   [safe_name, pw_hash])
        db.commit()
        uid = db.execute('SELECT id FROM users WHERE username = ?', [safe_name]).fetchone()['id']
        db.close()
        return {'success': True, 'user_id': uid, 'username': safe_name, 'score': 0,
                'message': f'Created bot account "{safe_name}"'}
    except Exception as e:
        db.close()
        return {'error': f'Could not create bot user: {e}'}


def agent_login(username, password):
    if not username or not password:
        return {'error': 'username and password are required'}
    db = get_db()
    user = db.execute(
        'SELECT id, username, score, password FROM users WHERE username = ?',
        [username]).fetchone()
    db.close()
    if not user or not check_password_hash(user['password'], password):
        return {'error': f'Invalid credentials for "{username}"'}
    return {'success': True, 'user_id': user['id'], 'username': user['username'],
            'score': user['score'],
            'message': f'Logged in as "{user["username"]}" ({user["score"]} pts)'}


def agent_execute_tool(name, tool_input, ctx):
    """ctx is a mutable dict with at least {'user_id': <int|None>}."""
    uid = ctx.get('user_id')
    if name == 'create_bot_user':
        result = agent_create_bot_user(tool_input.get('bot_name', 'VulnSniff'))
        if result.get('success'):
            ctx['user_id'] = result['user_id']
        return result
    if name == 'login':
        result = agent_login(tool_input.get('username', ''), tool_input.get('password', ''))
        if result.get('success'):
            ctx['user_id'] = result['user_id']
        return result
    if name == 'list_challenges':
        return agent_list_challenges(uid)
    if name == 'solve_challenge':
        cid = tool_input.get('challenge_id', '')
        ctx.setdefault('challenge_start_times', {})[cid] = datetime.utcnow().isoformat()
        return agent_solve_challenge(cid)
    if name == 'submit_flag':
        cid = tool_input.get('challenge_id', '')
        started_at = ctx.get('challenge_start_times', {}).get(cid, '')
        solved_at  = datetime.utcnow().isoformat()
        return agent_submit_flag(cid, tool_input.get('flag', ''), ctx.get('user_id'),
                                 ctx.get('model', ''), started_at, solved_at)
    return {'error': f'Unknown tool: {name}'}


# ── Side chat panel (Anthropic) ───────────────────────────────────────────────
def _get_challenge_name(cid):
    if cid in CHALLENGES:
        return CHALLENGES[cid]['name']
    db = get_db()
    row = db.execute('SELECT name FROM dynamic_challenges WHERE id = ?', [cid]).fetchone()
    db.close()
    return row['name'] if row else cid


@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    if not CHAT_API_KEY:
        return jsonify({'error': 'Chat is not configured. Add ANTHROPIC_API_KEY to the '
                                 '.env file and restart the server.'}), 503

    req_data = request.get_json(silent=True) or {}
    history = req_data.get('messages', [])
    if not isinstance(history, list) or not history:
        return jsonify({'error': 'No messages provided.'}), 400
    requested_model = req_data.get('model', '')
    model = requested_model if requested_model in CHAT_ALLOWED_MODELS else CHAT_MODEL
    mode = req_data.get('mode', 'chat')
    page_path = str(req_data.get('page_path', ''))[:200]
    user_id = session.get('user_id')
    page_context = build_page_context(page_path, user_id)
    system = CHAT_SYSTEM_PROMPT + page_context

    messages = []
    for m in history[-20:]:
        if not isinstance(m, dict):
            continue
        role = m.get('role')
        content = m.get('content', '')
        if role in ('user', 'assistant') and isinstance(content, str) and content.strip():
            messages.append({'role': role, 'content': content[:4000]})
    if not messages:
        return jsonify({'error': 'No valid messages provided.'}), 400

    api_headers = {
        'x-api-key': CHAT_API_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Type': 'application/json',
    }
    loop_messages = list(messages)
    agent_ctx = {'user_id': user_id, 'model': model, 'challenge_start_times': {}}

    def sse(obj):
        return f"data: {json.dumps(obj)}\n\n"

    def generate():
        reply_parts = []
        try:
            for _turn in range(40):
                body = {
                    'model': model,
                    'max_tokens': 10000 if mode == 'reasoning' else 2048,
                    'system': system,
                    'messages': loop_messages,
                    'tools': AGENT_TOOLS,
                }
                if mode == 'reasoning' and model in THINKING_MODELS:
                    body['thinking'] = {'type': 'enabled', 'budget_tokens': 8000}

                api_resp = requests.post('https://api.anthropic.com/v1/messages',
                                         headers=api_headers, json=body, timeout=120)
                api_resp.raise_for_status()
                rdata = api_resp.json()
                content = rdata.get('content', [])
                stop_reason = rdata.get('stop_reason')

                turn_text = ''.join(b['text'] for b in content if b.get('type') == 'text')
                if turn_text.strip():
                    reply_parts.append(turn_text.strip())

                if stop_reason != 'tool_use':
                    break

                loop_messages.append({'role': 'assistant', 'content': content})
                tool_results = []
                for block in content:
                    if block.get('type') != 'tool_use':
                        continue
                    tool_name = block['name']
                    tool_input = block.get('input', {})

                    if tool_name == 'solve_challenge':
                        cid = tool_input.get('challenge_id', '')
                        yield sse({'type': 'status', 'text': f'🔍 Attempting: {_get_challenge_name(cid)}…'})

                    elif tool_name == 'list_challenges':
                        yield sse({'type': 'status', 'text': '📋 Listing available challenges…'})

                    elif tool_name == 'create_bot_user':
                        yield sse({'type': 'status', 'text': f'👤 Setting up bot account…'})

                    result = agent_execute_tool(tool_name, tool_input, agent_ctx)

                    if tool_name == 'submit_flag':
                        cid = tool_input.get('challenge_id', '')
                        name = _get_challenge_name(cid)
                        if result.get('success'):
                            pts = result.get('points', 0)
                            yield sse({'type': 'status', 'text': f'✓ Solved {name} — +{pts} pts', 'solved': True})
                        elif result.get('already_solved'):
                            yield sse({'type': 'status', 'text': f'↩ {name} already solved'})
                        elif result.get('error'):
                            yield sse({'type': 'status', 'text': f'✗ {name}: {result["error"]}'})

                    tool_results.append({
                        'type': 'tool_result',
                        'tool_use_id': block['id'],
                        'content': json.dumps(result),
                    })
                loop_messages.append({'role': 'user', 'content': tool_results})

        except requests.exceptions.RequestException as e:
            yield sse({'type': 'error', 'error': f'Could not reach the model: {e}'})
            return
        except (KeyError, IndexError, ValueError) as e:
            yield sse({'type': 'error', 'error': f'Unexpected response from the model: {e}'})
            return

        yield sse({'type': 'done', 'reply': '\n\n'.join(reply_parts), 'model': model, 'mode': mode})

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )

# ── Challenge 1: SQL Injection — Login Bypass ─────────────────────────────────
@app.route('/challenges/sqli', methods=['GET', 'POST'])
def sqli():
    result = None
    query_shown = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        # VULNERABLE: raw string interpolation — never do this in real code
        query = f"SELECT * FROM sqli_users WHERE username = '{username}' AND password = '{password}'"
        query_shown = query
        if 'user_id' in session:
            log_activity(session['user_id'], 'sqli', f'Login attempt — username: {username!r}')
        try:
            db = get_db()
            row = db.execute(query).fetchone()
            db.close()
            if row:
                result = {'success': True, 'user': row['username'], 'secret': row['secret']}
            else:
                result = {'success': False, 'message': 'Invalid credentials.'}
        except Exception as e:
            result = {'success': False, 'message': f'DB Error: {e}'}
    return render_template('challenges/sqli.html', result=result, query=query_shown,
                           challenge=CHALLENGES['sqli'])

# ── Challenge 2: SQL Injection — Data Exfiltration ───────────────────────────
@app.route('/challenges/sqli2')
def sqli2():
    search = request.args.get('search', '')
    products = []
    query_shown = None
    error = None
    if search:
        # VULNERABLE: UNION-based injection possible
        query = f"SELECT id, name, price, description FROM products WHERE name LIKE '%{search}%'"
        query_shown = query
        if 'user_id' in session:
            log_activity(session['user_id'], 'sqli2', f'Search query: {search!r}')
        try:
            db = get_db()
            products = db.execute(query).fetchall()
            db.close()
        except Exception as e:
            error = str(e)
    return render_template('challenges/sqli2.html', products=products, search=search,
                           query=query_shown, error=error, challenge=CHALLENGES['sqli2'])

# ── Challenge 3: Reflected XSS ────────────────────────────────────────────────
@app.route('/challenges/xss')
def xss():
    name = request.args.get('name', '')
    if name and 'user_id' in session:
        log_activity(session['user_id'], 'xss', f'Reflected XSS payload in ?name: {name!r}')
    resp = make_response(render_template('challenges/xss.html',
                                         name=name, challenge=CHALLENGES['xss']))
    # Flag is stored in a cookie — steal it with XSS
    resp.set_cookie('xss_flag', 'FLAG{xss_reflected_2024}', httponly=False)
    return resp

# ── Challenge 4: Stored XSS — Cookie Theft ───────────────────────────────────
@app.route('/challenges/xss_stored', methods=['GET', 'POST'])
def xss_stored():
    db = get_db()
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        author = request.form.get('author', 'Anonymous')
        # VULNERABLE: stored without sanitisation
        db.execute('INSERT INTO xss_comments (author, comment) VALUES (?, ?)', [author, comment])
        db.commit()
        if 'user_id' in session:
            log_activity(session['user_id'], 'xss_stored',
                         f'Posted comment as {author!r}: {comment!r}')
        return redirect(url_for('xss_stored'))
    comments = db.execute('SELECT * FROM xss_comments ORDER BY id DESC LIMIT 30').fetchall()
    db.close()
    resp = make_response(render_template('challenges/xss_stored.html',
                                          comments=comments, challenge=CHALLENGES['xss_stored']))
    resp.set_cookie('user_session', 'FLAG{xss_stored_cookie_stealer}', httponly=False)
    return resp

@app.route('/challenges/xss_stored/bot')
def xss_stored_bot():
    """Simulates an admin bot visiting the comment board."""
    db = get_db()
    comments = db.execute('SELECT comment FROM xss_comments').fetchall()
    db.close()
    scripts = [c['comment'] for c in comments
               if '<script' in c['comment'].lower() or 'onerror' in c['comment'].lower()
               or 'onload' in c['comment'].lower()]
    triggered = len(scripts) > 0
    return jsonify({
        'visited': True,
        'xss_triggered': triggered,
        'stolen_cookie': 'FLAG{xss_stored_cookie_stealer}' if triggered else None,
        'message': ('Admin cookie stolen! The admin had: user_session=FLAG{xss_stored_cookie_stealer}'
                    if triggered else 'No XSS payload found in comments.')
    })

# ── Challenge 5: CSRF — Email Hijack ──────────────────────────────────────────
@app.route('/challenges/csrf')
def csrf():
    db = get_db()
    victim = db.execute("SELECT * FROM csrf_users WHERE username = 'victim'").fetchone()
    db.close()
    changed = request.args.get('changed') == '1'
    flag = None
    if victim and victim['email'] != 'victim@example.com':
        flag = 'FLAG{csrf_token_missing_2024}'
    return render_template('challenges/csrf.html', victim=victim, changed=changed,
                           flag=flag, challenge=CHALLENGES['csrf'])

@app.route('/challenges/csrf/change_email', methods=['POST'])
def csrf_change_email():
    # VULNERABLE: no origin/CSRF-token check
    new_email = request.form.get('email', '').strip()
    if new_email:
        db = get_db()
        db.execute("UPDATE csrf_users SET email = ? WHERE username = 'victim'", [new_email])
        db.commit()
        db.close()
        if 'user_id' in session:
            log_activity(session['user_id'], 'csrf',
                         f"Changed victim's email to: {new_email!r}")
    return redirect(url_for('csrf') + '?changed=1')

@app.route('/challenges/csrf/reset', methods=['POST'])
def csrf_reset():
    db = get_db()
    db.execute("UPDATE csrf_users SET email = 'victim@example.com' WHERE username = 'victim'")
    db.commit()
    db.close()
    return redirect(url_for('csrf'))

# ── Challenge 6: Command Injection ────────────────────────────────────────────
@app.route('/challenges/cmdi', methods=['GET', 'POST'])
def cmdi():
    output = None
    command_run = None
    if request.method == 'POST':
        target = request.form.get('target', '')
        # VULNERABLE: shell=True with unsanitised input
        if os.name == 'nt':
            command_run = f'ping -n 1 {target}'
        else:
            command_run = f'ping -c 1 {target}'
        if 'user_id' in session:
            log_activity(session['user_id'], 'cmdi', f'Command injection via target: {target!r}')
        try:
            result = subprocess.run(command_run, shell=True, capture_output=True,
                                    text=True, timeout=10,
                                    cwd=os.path.dirname(__file__))
            output = (result.stdout or '') + (result.stderr or '')
        except subprocess.TimeoutExpired:
            output = 'Command timed out after 10 seconds.'
        except Exception as e:
            output = str(e)
    return render_template('challenges/cmdi.html', output=output,
                           command=command_run, challenge=CHALLENGES['cmdi'])

# ── Challenge 7: Path Traversal ───────────────────────────────────────────────
@app.route('/challenges/path')
def path_traversal():
    filename = request.args.get('file', 'welcome.txt')
    content = None
    error = None
    base_dir = os.path.join(os.path.dirname(__file__), 'static', 'files')
    # VULNERABLE: os.path.join can be escaped with leading / or ../
    filepath = os.path.join(base_dir, filename)
    if filename != 'welcome.txt' and 'user_id' in session:
        log_activity(session['user_id'], 'path', f'Accessed file path: {filename!r}')
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except FileNotFoundError:
        error = f'File not found: {filename}'
    except PermissionError:
        error = 'Permission denied.'
    except Exception as e:
        error = str(e)
    return render_template('challenges/path.html', content=content,
                           filename=filename, error=error, challenge=CHALLENGES['path'])

# ── AI: add dynamic challenge ─────────────────────────────────────────────────
VALID_VULN_TYPES = {'sqli_login','sqli_union','xss_reflected','xss_stored','cmdi','path','csrf'}
VALID_DIFFICULTIES = {'Easy','Medium','Hard'}
APP_DIR = os.path.dirname(__file__)

@app.route('/api/add_challenge', methods=['POST'])
@login_required
def api_add_challenge():
    data = request.get_json(silent=True) or {}
    name        = str(data.get('name', '')).strip()[:100]
    category    = str(data.get('category', 'Web')).strip()[:50]
    difficulty  = str(data.get('difficulty', 'Easy')).strip()
    points      = data.get('points', 100)
    vuln_type   = str(data.get('vuln_type', '')).strip()
    description = str(data.get('description', '')).strip()[:500]
    context     = str(data.get('context', '')).strip()[:1000]
    model       = str(data.get('model', '')).strip()[:100]
    if model not in CHAT_ALLOWED_MODELS:
        model = ''

    if not name or vuln_type not in VALID_VULN_TYPES:
        return jsonify({'error': 'Missing name or unsupported vuln_type.'}), 400
    if difficulty not in VALID_DIFFICULTIES:
        difficulty = 'Easy'
    try:
        points = max(50, min(500, int(points)))
    except (TypeError, ValueError):
        points = 100

    slug_base = re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_')[:32]
    slug = f"dyn_{slug_base}_{secrets.token_hex(3)}"
    flag = f"FLAG{{dyn_{secrets.token_hex(12)}}}"

    db = get_db()
    try:
        db.execute('''INSERT INTO dynamic_challenges
            (id, name, category, difficulty, points, vuln_type, description, context, flag, model)
            VALUES (?,?,?,?,?,?,?,?,?,?)''',
            [slug, name, category, difficulty, points, vuln_type, description, context, flag, model])

        if vuln_type == 'sqli_union':
            db.execute('INSERT INTO secret_flags (flag_name, flag_value) VALUES (?,?)',
                       [slug, flag])

        elif vuln_type in ('cmdi', 'path'):
            flag_path = os.path.join(APP_DIR, f'{slug}_flag.txt')
            with open(flag_path, 'w') as f:
                f.write(f'{flag}\n\nYou escaped the {vuln_type} vulnerability!\n')

        elif vuln_type == 'xss_stored':
            db.execute("INSERT INTO dynamic_comments (challenge_id, author, comment) "
                       "VALUES (?, 'System', 'Welcome to the community board!')", [slug])

        elif vuln_type == 'csrf':
            db.execute("INSERT OR IGNORE INTO csrf_users (username, email) VALUES (?, 'victim@example.com')",
                       [f'victim_{slug}'])

        db.commit()
    except Exception as e:
        db.rollback()
        db.close()
        return jsonify({'error': str(e)}), 500
    db.close()
    return jsonify({'success': True, 'id': slug, 'url': f'/challenges/d/{slug}'})

# ── Dynamic challenge dispatcher ──────────────────────────────────────────────
@app.route('/challenges/d/<cid>', methods=['GET', 'POST'])
def dynamic_challenge(cid):
    db = get_db()
    row = db.execute('SELECT * FROM dynamic_challenges WHERE id = ?', [cid]).fetchone()
    db.close()
    if not row:
        abort(404)
    ch = dict(row)
    vt = ch['vuln_type']

    if vt == 'sqli_login':
        result, query_shown = None, None
        if request.method == 'POST':
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            query = f"SELECT * FROM sqli_users WHERE username = '{username}' AND password = '{password}'"
            query_shown = query
            if 'user_id' in session:
                log_activity(session['user_id'], cid, f'Login attempt — username: {username!r}')
            try:
                db2 = get_db()
                row2 = db2.execute(query).fetchone()
                db2.close()
                if row2:
                    result = {'success': True, 'user': row2['username'], 'secret': ch['flag']}
                else:
                    result = {'success': False, 'message': 'Invalid credentials.'}
            except Exception as e:
                result = {'success': False, 'message': f'DB Error: {e}'}
        return render_template('challenges/dynamic.html', ch=ch, result=result, query=query_shown)

    if vt == 'sqli_union':
        search = request.args.get('search', '')
        products, query_shown, error = [], None, None
        if search:
            query = f"SELECT id, name, price, description FROM products WHERE name LIKE '%{search}%'"
            query_shown = query
            if 'user_id' in session:
                log_activity(session['user_id'], cid, f'Search query: {search!r}')
            try:
                db2 = get_db()
                products = db2.execute(query).fetchall()
                db2.close()
            except Exception as e:
                error = str(e)
        return render_template('challenges/dynamic.html', ch=ch,
                               products=products, search=search, query=query_shown, error=error)

    if vt == 'xss_reflected':
        name = request.args.get('name', '')
        if name and 'user_id' in session:
            log_activity(session['user_id'], cid, f'XSS payload in ?name: {name!r}')
        resp = make_response(render_template('challenges/dynamic.html', ch=ch, name=name))
        resp.set_cookie(f'dyn_{cid}', ch['flag'], httponly=False)
        return resp

    if vt == 'xss_stored':
        if request.method == 'POST':
            comment = request.form.get('comment', '')
            author  = request.form.get('author', 'Anonymous')
            db2 = get_db()
            db2.execute('INSERT INTO dynamic_comments (challenge_id, author, comment) VALUES (?,?,?)',
                        [cid, author, comment])
            db2.commit()
            db2.close()
            if 'user_id' in session:
                log_activity(session['user_id'], cid, f'Posted comment as {author!r}: {comment!r}')
            return redirect(url_for('dynamic_challenge', cid=cid))
        db2 = get_db()
        comments = db2.execute(
            'SELECT * FROM dynamic_comments WHERE challenge_id = ? ORDER BY id DESC LIMIT 30',
            [cid]).fetchall()
        db2.close()
        resp = make_response(render_template('challenges/dynamic.html', ch=ch, comments=comments))
        resp.set_cookie(f'dyn_{cid}', ch['flag'], httponly=False)
        return resp

    if vt == 'cmdi':
        output, command_run = None, None
        if request.method == 'POST':
            target = request.form.get('target', '')
            command_run = f'ping -n 1 {target}' if os.name == 'nt' else f'ping -c 1 {target}'
            if 'user_id' in session:
                log_activity(session['user_id'], cid, f'Command injection via target: {target!r}')
            try:
                proc = subprocess.run(command_run, shell=True, capture_output=True,
                                      text=True, timeout=10, cwd=APP_DIR)
                output = (proc.stdout or '') + (proc.stderr or '')
            except subprocess.TimeoutExpired:
                output = 'Command timed out.'
            except Exception as e:
                output = str(e)
        return render_template('challenges/dynamic.html', ch=ch, output=output, command=command_run)

    if vt == 'path':
        filename = request.args.get('file', 'welcome.txt')
        base_dir = os.path.join(APP_DIR, 'static', 'files')
        filepath = os.path.join(base_dir, filename)
        content, error = None, None
        if filename != 'welcome.txt' and 'user_id' in session:
            log_activity(session['user_id'], cid, f'Accessed file path: {filename!r}')
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except FileNotFoundError:
            error = f'File not found: {filename}'
        except PermissionError:
            error = 'Permission denied.'
        except Exception as e:
            error = str(e)
        return render_template('challenges/dynamic.html', ch=ch,
                               content=content, filename=filename, error=error)

    if vt == 'csrf':
        victim_key = f'victim_{cid}'
        db2 = get_db()
        victim = db2.execute('SELECT * FROM csrf_users WHERE username = ?', [victim_key]).fetchone()
        db2.close()
        changed = request.args.get('changed') == '1'
        flag = ch['flag'] if (victim and victim['email'] != 'victim@example.com') else None
        return render_template('challenges/dynamic.html', ch=ch,
                               victim=victim, changed=changed, flag=flag)

    abort(404)

@app.route('/challenges/d/<cid>/change_email', methods=['POST'])
def dynamic_csrf_change_email(cid):
    new_email = request.form.get('email', '').strip()
    if new_email:
        db = get_db()
        db.execute('UPDATE csrf_users SET email = ? WHERE username = ?',
                   [new_email, f'victim_{cid}'])
        db.commit()
        db.close()
        if 'user_id' in session:
            log_activity(session['user_id'], cid, f"Changed victim's email to: {new_email!r}")
    return redirect(url_for('dynamic_challenge', cid=cid) + '?changed=1')

@app.route('/challenges/d/<cid>/reset_csrf', methods=['POST'])
def dynamic_csrf_reset(cid):
    db = get_db()
    db.execute("UPDATE csrf_users SET email = 'victim@example.com' WHERE username = ?",
               [f'victim_{cid}'])
    db.commit()
    db.close()
    return redirect(url_for('dynamic_challenge', cid=cid))

@app.route('/challenges/d/<cid>/bot')
def dynamic_xss_bot(cid):
    db = get_db()
    ch = db.execute('SELECT flag FROM dynamic_challenges WHERE id = ?', [cid]).fetchone()
    if not ch:
        db.close()
        return jsonify({'error': 'Challenge not found'}), 404
    comments = db.execute(
        'SELECT comment FROM dynamic_comments WHERE challenge_id = ?', [cid]
    ).fetchall()
    db.close()
    triggered = any('<script' in c['comment'].lower() or 'onerror' in c['comment'].lower()
                    or 'onload' in c['comment'].lower() for c in comments)
    flag = ch['flag']
    return jsonify({
        'visited': True, 'xss_triggered': triggered,
        'stolen_cookie': flag if triggered else None,
        'message': (f'Admin cookie stolen! The flag is: {flag}'
                    if triggered else 'No XSS payload found in comments.')
    })

# ── Vulnerable code snippets (for post-mortem before/after) ──────────────────
CHALLENGE_VULN_CODE = {
    'sqli': (
        'Python — app.py',
        '''# VULNERABLE
query = f"SELECT * FROM sqli_users WHERE username = \'{username}\' AND password = \'{password}\'"
row = db.execute(query).fetchone()''',
    ),
    'sqli2': (
        'Python — app.py',
        '''# VULNERABLE
query = f"SELECT id, name, price, description FROM products WHERE name LIKE \'%{search}%\'"
products = db.execute(query).fetchall()''',
    ),
    'xss': (
        'Jinja2 template — xss.html',
        '''<!-- VULNERABLE: | safe disables auto-escaping, raw user input injected into DOM -->
<p>Hello, {{ name | safe }}!</p>''',
    ),
    'xss_stored': (
        'Jinja2 template — xss_stored.html',
        '''<!-- VULNERABLE: comment stored without sanitisation and rendered with | safe -->
<div class="comment-body">{{ c.comment | safe }}</div>''',
    ),
    'csrf': (
        'Python — app.py',
        '''# VULNERABLE: no CSRF token or Origin check — any site can POST to this endpoint
@app.route(\'/challenges/csrf/change_email\', methods=[\'POST\'])
def csrf_change_email():
    new_email = request.form.get(\'email\', \'\').strip()
    db.execute("UPDATE csrf_users SET email = ? WHERE username = \'victim\'", [new_email])''',
    ),
    'cmdi': (
        'Python — app.py',
        '''# VULNERABLE: unsanitised user input passed directly to shell
command_run = f\'ping -c 1 {target}\'
result = subprocess.run(command_run, shell=True, capture_output=True, text=True)''',
    ),
    'path': (
        'Python — app.py',
        '''# VULNERABLE: os.path.join does not prevent ../ escape from base_dir
base_dir = os.path.join(os.path.dirname(__file__), \'static\', \'files\')
filepath = os.path.join(base_dir, filename)
with open(filepath, \'r\') as f:
    content = f.read()''',
    ),
}

# ── AI post-mortem analysis ───────────────────────────────────────────────────
@app.route('/api/analyze', methods=['POST'])
@login_required
def api_analyze():
    if not CHAT_API_KEY:
        return jsonify({'error': 'AI analysis not configured. Add ANTHROPIC_API_KEY to .env.'}), 503

    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    challenge_id = data.get('challenge_id', '').strip()

    if not username or not challenge_id:
        return jsonify({'error': 'Invalid request.'}), 400

    db = get_db()

    # Resolve challenge from static registry or dynamic table
    if challenge_id in CHALLENGES:
        ch = dict(CHALLENGES[challenge_id])
        ch.setdefault('desc', ch.get('desc', ''))
    else:
        dyn = db.execute('SELECT * FROM dynamic_challenges WHERE id = ?', [challenge_id]).fetchone()
        if not dyn:
            db.close()
            return jsonify({'error': 'Invalid request.'}), 400
        dyn = dict(dyn)
        ch = {
            'name': dyn['name'],
            'category': dyn['category'],
            'difficulty': dyn['difficulty'],
            'points': dyn['points'],
            'desc': dyn.get('description', ''),
        }

    user = db.execute('SELECT * FROM users WHERE username = ?', [username]).fetchone()
    if not user:
        db.close()
        return jsonify({'error': 'User not found.'}), 404

    solved = db.execute(
        'SELECT solved_at FROM solved WHERE user_id = ? AND challenge_id = ?',
        [user['id'], challenge_id]
    ).fetchone()

    activity_rows = db.execute(
        'SELECT detail, ts FROM activity WHERE user_id = ? AND challenge_id = ? ORDER BY ts ASC',
        [user['id'], challenge_id]
    ).fetchall()
    db.close()

    PLACEHOLDER = 'Solved before activity logging was enabled'
    vuln_label, vuln_code = CHALLENGE_VULN_CODE.get(challenge_id, ('', ''))
    is_solved = solved is not None
    real_rows = [r for r in activity_rows if PLACEHOLDER not in r['detail']]
    has_activity = len(real_rows) > 0
    status = f"SOLVED on {solved['solved_at']}" if is_solved else "NOT YET SOLVED"
    activity_text = '\n'.join(f"  [{r['ts']}] {r['detail']}" for r in real_rows)

    vuln_block = f"""
Vulnerable code ({vuln_label}):
```
{vuln_code}
```
""" if vuln_code else ''

    before_after_instruction = """
**Before / After** — Show the vulnerable code as a `before` block, then the corrected version as an `after` block, with a one-sentence explanation of what changed and why it fixes the vulnerability.
"""

    if has_activity:
        prompt = f"""Perform a post-mortem security analysis of this CTF challenge attempt.

Challenge: {ch['name']}
Category: {ch['category']} | Difficulty: {ch['difficulty']} | Points: {ch['points']}
Description: {ch['desc']}
Status: {status}
{vuln_block}
Student activity log (chronological):
{activity_text}

Provide a concise post-mortem in exactly these five sections:

**Approach Assessment** — Was the technique correct and efficient? Were there unnecessary or incorrect attempts before the solution?

**Vulnerability Exploited** — What specific vulnerability was abused and how does it work?

**Correctness Verdict** — Was the final payload/solution the right approach, or did they get lucky with a non-standard path?
{before_after_instruction}
**Key Takeaway** — One actionable learning point for hardening this type of vulnerability.

Keep each section to 2-3 sentences except Before/After. Use inline `code` for payloads, queries, or commands."""
    else:
        prompt = f"""You are writing a post-mortem for a CTF challenge that was successfully solved.
Write this as a definitive post-mortem of the correct/optimal approach. Do NOT mention missing \
data or logs — write as if you observed the ideal solve.

Challenge: {ch['name']}
Category: {ch['category']} | Difficulty: {ch['difficulty']} | Points: {ch['points']}
Description: {ch['desc']}
Status: {status}
{vuln_block}
Cover exactly these five sections:

**Approach Assessment** — Describe the correct, efficient technique. What common wrong turns do students take?

**Vulnerability Exploited** — What specific vulnerability exists and how does the exploit work mechanically?

**Correctness Verdict** — What does the correct final payload/exploit look like and why is it the right solution?
{before_after_instruction}
**Key Takeaway** — One actionable learning point for hardening this type of vulnerability in real applications.

Keep each section to 2-3 sentences except Before/After. Use inline `code` for payloads, queries, or commands."""

    try:
        resp = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers={
                'x-api-key': CHAT_API_KEY,
                'anthropic-version': '2023-06-01',
                'Content-Type': 'application/json',
            },
            json={
                'model': CHAT_MODEL,
                'max_tokens': 2048,
                'system': CHAT_SYSTEM_PROMPT,
                'messages': [{'role': 'user', 'content': prompt}],
            },
            timeout=60,
        )
        resp.raise_for_status()
        analysis = resp.json()['content'][0]['text']
        return jsonify({'analysis': analysis, 'model': CHAT_MODEL})
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Could not reach the model: {e}'}), 502
    except (KeyError, IndexError, ValueError):
        return jsonify({'error': 'Unexpected response from the model.'}), 502

# ── User profile ──────────────────────────────────────────────────────────────
@app.route('/user/<username>')
def user_profile(username):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', [username]).fetchone()
    if not user:
        db.close()
        return render_template('404.html'), 404

    solved_rows = db.execute(
        'SELECT challenge_id, solved_at, solver_model, started_at FROM solved WHERE user_id = ? ORDER BY solved_at ASC',
        [user['id']]
    ).fetchall()
    solved_ids = {r['challenge_id'] for r in solved_rows}
    solved_map = {r['challenge_id']: r['solved_at'] for r in solved_rows}
    solver_model_map = {r['challenge_id']: (r['solver_model'] or '') for r in solved_rows}
    started_at_map = {r['challenge_id']: (r['started_at'] or '') for r in solved_rows}

    activity_rows = db.execute(
        'SELECT challenge_id, detail, ts FROM activity WHERE user_id = ? ORDER BY ts DESC',
        [user['id']]
    ).fetchall()

    rank_row = db.execute(
        'SELECT COUNT(*) as r FROM users WHERE score > ?', [user['score']]
    ).fetchone()
    rank = rank_row['r'] + 1

    dyn_rows = db.execute('SELECT * FROM dynamic_challenges ORDER BY created_at ASC').fetchall()
    dynamic_challenges = [dict(r) for r in dyn_rows]

    db.close()

    # Group activity by challenge (ascending so we can index correctly)
    activity_by_challenge = {}
    for row in reversed(activity_rows):  # activity_rows is DESC, reverse to get ASC
        activity_by_challenge.setdefault(row['challenge_id'], []).append({
            'detail': row['detail'], 'ts': row['ts'], 'status': 'neutral'
        })

    # Tag each entry: last entry at-or-before solved_at → correct (green),
    # earlier entries → incorrect (red), entries after solve → neutral.
    PLACEHOLDER = 'Solved before activity logging was enabled'
    for cid, entries in activity_by_challenge.items():
        if cid not in solved_map:
            continue
        solved_time = solved_map[cid]
        last_correct_idx = None
        for i, e in enumerate(entries):
            if PLACEHOLDER not in e['detail'] and e['ts'] <= solved_time:
                last_correct_idx = i
        for i, e in enumerate(entries):
            if PLACEHOLDER in e['detail']:
                e['status'] = 'neutral'
            elif e['ts'] > solved_time:
                e['status'] = 'neutral'
            elif i == last_correct_idx:
                e['status'] = 'correct'
            else:
                e['status'] = 'incorrect'

    def _build_entry(cid, ch):
        entry = dict(ch, id=cid)
        if cid in solved_ids:
            entry['solved_at'] = solved_map[cid]
            entry['solver_model'] = solver_model_map.get(cid, '')
            entry['activity'] = activity_by_challenge.get(cid, [])
            solve_seconds = None
            start_ts = started_at_map.get(cid, '')
            end_ts = solved_map[cid]
            if start_ts and end_ts:
                try:
                    delta = datetime.fromisoformat(end_ts) - datetime.fromisoformat(start_ts)
                    solve_seconds = max(0.0, delta.total_seconds())
                except (ValueError, TypeError):
                    pass
            entry['solve_seconds'] = solve_seconds
            entry['solve_time'] = format_duration(solve_seconds) if solve_seconds is not None else None
            return 'solved', entry
        else:
            entry['activity'] = activity_by_challenge.get(cid, [])
            return 'unsolved', entry

    solved_challenges = []
    unsolved_challenges = []

    for cid, ch in CHALLENGES.items():
        bucket, entry = _build_entry(cid, ch)
        (solved_challenges if bucket == 'solved' else unsolved_challenges).append(entry)

    for dch in dynamic_challenges:
        cid = dch['id']
        ch = {
            'name': dch['name'],
            'points': dch['points'],
            'difficulty': dch['difficulty'],
            'category': dch['category'],
            'desc': dch.get('description', ''),
            'dynamic': True,
            'creator_model': dch.get('model', ''),
        }
        bucket, entry = _build_entry(cid, ch)
        (solved_challenges if bucket == 'solved' else unsolved_challenges).append(entry)

    solved_challenges.sort(key=lambda x: x['solved_at'])

    known_times = [ch['solve_seconds'] for ch in solved_challenges if ch.get('solve_seconds') is not None]
    total_solve_time = format_duration(sum(known_times)) if known_times else None

    return render_template('user_profile.html',
                           profile_user=user, rank=rank,
                           solved_challenges=solved_challenges,
                           unsolved_challenges=unsolved_challenges,
                           total=len(CHALLENGES) + len(dynamic_challenges),
                           total_solve_time=total_solve_time)

if __name__ == '__main__':
    ensure_activity_table()
    app.run(debug=True, host='0.0.0.0', port=8080)
