import sqlite3
from contextlib import contextmanager

DATABASE = 'database.db'

DIFFICULTY_SCORES = {
    'login': ('Easy', 10),
    'xss': ('Easy', 10),
    'csrf': ('Easy', 10),
    'upload': ('Easy', 10),
    'idor': ('Medium', 20),
    'ssrf': ('Hard', 30),
    'xxe': ('Hard', 30),
    'deserialize': ('Hard', 30),
    'reflected_xss': ('Medium', 20),
    'broken_auth': ('Medium', 20),
    'dom_xss': ('Medium', 20),
    'ssti': ('Advanced', 40),
    'csrf_page': ('Medium', 20),
}

@contextmanager
def db_connection():
    """Context manager for database connections with row_factory set."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

get_db_connection = db_connection

def init_db():
    with get_db_connection() as conn:
        # Drop existing tables to ensure a clean schema
        conn.execute('DROP TABLE IF EXISTS users')
        conn.execute('DROP TABLE IF EXISTS progress')
        conn.execute('DROP TABLE IF EXISTS logs')
        conn.execute('DROP TABLE IF EXISTS reports')
        conn.execute('DROP TABLE IF EXISTS comments')

        # Create users table with id column
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user'
            )
        ''')

        # Create progress table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS progress (
                user TEXT NOT NULL,
                challenge TEXT NOT NULL,
                score INTEGER NOT NULL,
                PRIMARY KEY (user, challenge)
            )
        ''')

        # Create logs table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                timestamp TEXT NOT NULL,
                user TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL
            )
        ''')

        # Create reports table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                timestamp TEXT NOT NULL,
                user TEXT NOT NULL,
                challenge TEXT NOT NULL,
                writeup TEXT NOT NULL
            )
        ''')

        # Create comments table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                content TEXT NOT NULL,
                date_posted TEXT NOT NULL
            )
        ''')

        # Insert default users
        conn.execute("INSERT OR IGNORE INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                     ("admin", "password", "admin@example.com", "admin"))
        conn.execute("INSERT OR IGNORE INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                     ("user2", "password2", "user2@example.com", "user"))

        # Insert default comments
        conn.execute("INSERT OR IGNORE INTO comments (username, content, date_posted) VALUES (?, ?, ?)",
                     ("admin", "Welcome to the comments section!", "2025-06-16 17:30:00"))
        conn.execute("INSERT OR IGNORE INTO comments (username, content, date_posted) VALUES (?, ?, ?)",
                     ("user2", "This is a test comment.", "2025-06-16 17:31:00"))

        users = conn.execute("SELECT * FROM users").fetchall()
        comments = conn.execute("SELECT * FROM comments").fetchall()
        print(f"Users table after init: {users}")
        print(f"Comments table after init: {comments}")
        conn.commit()

def update_progress(user, challenge):
    if challenge not in DIFFICULTY_SCORES:
        print(f"Error: Challenge '{challenge}' not found in DIFFICULTY_SCORES")
        return
    with get_db_connection() as conn:
        existing = conn.execute("SELECT * FROM progress WHERE user = ? AND challenge = ?", (user, challenge)).fetchone()
        if not existing:
            difficulty, score = DIFFICULTY_SCORES.get(challenge, ('Easy', 10))
            conn.execute("INSERT INTO progress (user, challenge, score) VALUES (?, ?, ?)", (user, challenge, score))
            conn.commit()
            log_action(user, "Progress Update", f"Completed challenge: {challenge} with score {score}")

def get_progress(user):
    try:
        with db_connection() as conn:
            progress = conn.execute(
                "SELECT challenge, score FROM progress WHERE user = ?",
                (user,)
            ).fetchall()
        completed_challenges = [row['challenge'] for row in progress]
        total_score = sum(row['score'] for row in progress)
        total_possible_score = sum(score for _, score in DIFFICULTY_SCORES.values())
        completion_percentage = (len(completed_challenges) / len(DIFFICULTY_SCORES)) * 100 if DIFFICULTY_SCORES else 0
        return progress, total_score, total_possible_score, completion_percentage
    except Exception as e:
        print(f"Error in get_progress for user {user}: {str(e)}")
        return [], 0, sum(score for _, score in DIFFICULTY_SCORES.values()), 0

def log_action(user, action, details):
    timestamp = "2025-06-17 10:58:00"
    print(f"Logging action: {timestamp} - {user} - {action} - {details}")
    with get_db_connection() as conn:
        conn.execute("INSERT INTO logs (timestamp, user, action, details) VALUES (?, ?, ?, ?)",
                     (timestamp, user, action, details))
        conn.commit()