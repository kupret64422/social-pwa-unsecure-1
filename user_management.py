import sqlite3 as sql
import time
import random
import os

# ─────────────────────────────────────────────────────────────────────────────
#  user_management.py
#  Handles all direct database operations for the Unsecure Social PWA.
#
#  INTENTIONAL VULNERABILITIES (for educational use):
#    1. SQL Injection      — f-string queries throughout
#    2. Plaintext passwords — no hashing applied at any point
#    3. Timing side-channel — sleep only fires when username EXISTS
#    4. No input validation — any string accepted as username/password
#    5. IDOR-equivalent    — username passed from client-side hidden field
# ─────────────────────────────────────────────────────────────────────────────

# Absolute paths — works regardless of where `python main.py` is called from
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "database_files", "database.db")
LOG_PATH = os.path.join(BASE_DIR, "visitor_log.txt")


def insertUser(username, password, DoB, bio=""):
    """
    Insert a new user.
    VULNERABILITY: Password stored as plaintext — no bcrypt/argon2 hashing.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth, bio) VALUES (?,?,?,?)",
        (username, password, DoB, bio),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    """
    Authenticate a user.
    FIXED: Using parameterized queries to prevent SQL injection.
    NOTE: Timing side-channel and plaintext passwords remain as educational examples.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()

    # SECURE: Parameterized query prevents SQL injection
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()

    if user_row is None:
        con.close()
        return False  # Fast path — no sleep here (timing leak)
    else:
        # VULNERABILITY: Timing side-channel — delay ONLY when username found
        time.sleep(random.randint(80, 90) / 1000)

        try:
            with open(LOG_PATH, "r") as f:
                count = int(f.read().strip() or 0)
            with open(LOG_PATH, "w") as f:
                f.write(str(count + 1))
        except Exception:
            pass

        # SECURE: Parameterized query prevents SQL injection
        cur.execute("SELECT * FROM users WHERE password = ?", (password,))
        result = cur.fetchone()
        con.close()
        return result is not None


def insertPost(author, content):
    """
    Insert a post.
    FIXED: Using parameterized query to prevent SQL injection.
    NOTE: IDOR vulnerability (author from hidden field) remains as educational example.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    # SECURE: Parameterized query prevents SQL injection
    cur.execute("INSERT INTO posts (author, content) VALUES (?,?)", (author, content))
    con.commit()
    con.close()


def getPosts():
    """
    Get all posts newest-first.
    NOTE: Content returned here is rendered with |safe in feed.html — stored XSS.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    data = cur.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    con.close()
    return data


def getUserProfile(username):
    """
    Get a user profile row.
    FIXED: Using parameterized query to prevent SQL injection.
    NOTE: Missing authentication check remains as educational example.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    # SECURE: Parameterized query prevents SQL injection
    cur.execute("SELECT id, username, dateOfBirth, bio, role FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    return row


def getMessages(username):
    """
    Get inbox for a user.
    FIXED: Using parameterized query to prevent SQL injection.
    NOTE: Missing authentication check remains as educational example.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    # SECURE: Parameterized query prevents SQL injection
    cur.execute("SELECT * FROM messages WHERE recipient = ? ORDER BY id DESC", (username,))
    rows = cur.fetchall()
    con.close()
    return rows


def sendMessage(sender, recipient, body):
    """
    Send a DM.
    FIXED: Using parameterized query to prevent SQL injection.
    NOTE: IDOR vulnerability (sender from hidden field) remains as educational example.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    # SECURE: Parameterized query prevents SQL injection
    cur.execute("INSERT INTO messages (sender, recipient, body) VALUES (?,?,?)", (sender, recipient, body))
    con.commit()
    con.close()


def getVisitorCount():
    """Return login attempt count."""
    try:
        with open(LOG_PATH, "r") as f:
            return int(f.read().strip() or 0)
    except Exception:
        return 0
