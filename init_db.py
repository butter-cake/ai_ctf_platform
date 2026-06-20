"""Initialize the CTF platform database and static files."""

import sqlite3
import os
import hashlib

DATABASE = os.path.join(os.path.dirname(__file__), 'ctf.db')
BASE = os.path.dirname(__file__)


def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # ── CTF platform tables ──────────────────────────────────────────────────
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        score    INTEGER DEFAULT 0
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS solved (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id      INTEGER NOT NULL,
        challenge_id TEXT NOT NULL,
        solved_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, challenge_id)
    )''')

    # ── Challenge 1 & 2: SQLi tables ────────────────────────────────────────
    c.execute('''CREATE TABLE IF NOT EXISTS sqli_users (
        id       INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        secret   TEXT
    )''')
    c.executemany("INSERT OR IGNORE INTO sqli_users VALUES (?,?,?,?)", [
        (1, 'admin',  'c3c8e6a89e88b3621ad5e9f4d57eaff3', 'FLAG{sqli_bypass_login_2024}'),
        (2, 'alice',  'password123',                        'Nothing special here.'),
        (3, 'bob',    'qwerty',                              'Keep looking…'),
        (4, 'charlie','letmein',                             'Not the flag.'),
    ])

    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id          INTEGER PRIMARY KEY,
        name        TEXT,
        price       REAL,
        description TEXT
    )''')
    c.executemany("INSERT OR IGNORE INTO products VALUES (?,?,?,?)", [
        (1, 'Widget Alpha',  9.99,  'A standard-grade widget.'),
        (2, 'Widget Beta',  19.99,  'A mid-tier widget with extras.'),
        (3, 'Gadget Pro',   49.99,  'High-performance gadget.'),
        (4, 'Mega Gadget', 149.99,  'Enterprise-class gadget.'),
    ])

    # Hidden table — reachable via UNION injection
    c.execute('''CREATE TABLE IF NOT EXISTS secret_flags (
        id         INTEGER PRIMARY KEY,
        flag_name  TEXT,
        flag_value TEXT
    )''')
    c.execute("INSERT OR IGNORE INTO secret_flags VALUES (1,'sqli2','FLAG{sqli_union_select_2024}')")

    # ── Challenge 4: Stored XSS table ────────────────────────────────────────
    c.execute('''CREATE TABLE IF NOT EXISTS xss_comments (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        author     TEXT,
        comment    TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute("INSERT OR IGNORE INTO xss_comments (id,author,comment) VALUES "
              "(1,'System','Welcome to the community board! Share your thoughts below.')")

    # ── Challenge 5: CSRF victim account ─────────────────────────────────────
    c.execute('''CREATE TABLE IF NOT EXISTS csrf_users (
        id       INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        email    TEXT
    )''')
    c.execute("INSERT OR IGNORE INTO csrf_users VALUES (1,'victim','victim@example.com')")

    # ── Activity log (user profile detail) ───────────────────────────────────
    c.execute('''CREATE TABLE IF NOT EXISTS activity (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id      INTEGER NOT NULL,
        challenge_id TEXT NOT NULL,
        detail       TEXT NOT NULL,
        ts           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    conn.commit()
    conn.close()
    print("[+] Database initialised:", DATABASE)


def create_files():
    files_dir = os.path.join(BASE, 'static', 'files')
    os.makedirs(files_dir, exist_ok=True)

    file_contents = {
        'welcome.txt': (
            'Welcome to VulnLab File Browser!\n'
            '================================\n\n'
            'Available files:\n'
            '  - welcome.txt  (you are here)\n'
            '  - about.txt\n'
            '  - readme.txt\n\n'
            'Try reading them with ?file=about.txt'
        ),
        'about.txt': (
            'VulnLab File Server v1.0\n'
            '------------------------\n'
            'This service lets you read files from the /static/files directory.\n'
            'Or does it...?\n'
        ),
        'readme.txt': (
            'README\n======\n'
            'This is a simple read-only file server.\n'
            'Files are stored in /static/files/.\n'
            'There is definitely nothing interesting outside this folder.\n'
        ),
    }

    for name, content in file_contents.items():
        path = os.path.join(files_dir, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

    # Secret flag file one level above static/files — reachable via ../../
    flag_path = os.path.join(BASE, 'ctf_flag_path.txt')
    with open(flag_path, 'w', encoding='utf-8') as f:
        f.write(
            'FLAG{path_traversal_etc_passwd}\n\n'
            'Congratulations! You escaped the web root via path traversal.\n'
            'In a real Linux server this could expose /etc/passwd, SSH keys,\n'
            'source code, or database credentials.\n'
        )

    print("[+] Static files created in:", files_dir)
    print("[+] Path traversal flag file:", flag_path)


if __name__ == '__main__':
    init_db()
    create_files()
    print("\n[OK] VulnLab is ready. Run:  python app.py")
