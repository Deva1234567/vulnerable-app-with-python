import sqlite3

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        comment TEXT NOT NULL
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS progress (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL,
        challenge TEXT NOT NULL,
        score INTEGER NOT NULL,
        UNIQUE(user, challenge)
    )
''')


cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('admin', 'admin123'))
cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('user1', 'password1'))
cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('user2', 'password2'))

conn.commit()
conn.close()

print("Database initialized successfully!")