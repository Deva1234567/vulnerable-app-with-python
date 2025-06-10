Vulnerable Web App for Learning
Overview
A PHP and Flask-based web app with vulnerabilities (XSS, SQLi, CSRF, RCE, JWT, IDOR, SSRF, XXE, Deserialization).
Updates (11:56 PM IST, June 5, 2025)

Content: Added SQLi query display, CSRF malicious example, severity ratings, OWASP references.
Fixed sqlite3.ProgrammingError by using context managers for database connections.
UI/UX: Added active nav indicators, success/failure feedback, vulnerability descriptions, reset buttons.
Fixed FileNotFoundError by ensuring upload directory exists and adding file listing.
Updated navbar title to 'Vulnerable App' and placed above tabs.
Removed /comments-log hint from dashboard.
Fixed sqlite3.OperationalError by ensuring progress table is created in database.py.
Added new vulnerabilities: Broken Auth, IDOR, SSRF, XXE, Security Misconfigs, Deserialization.
Enhanced features: Progress tracking, hints, reset buttons, solution walkthroughs.

XSS Testing

PHP: Stored XSS at /php/vulnerabilities/xss/stored.php with <script>alert('XSS')</script>.
Flask: Stored XSS at /comment with <script>alert('XSS')</script>.

Setup
PHP

Start XAMPP: Launch XAMPP Control Panel, start Apache and MySQL.
Initialize database: Open http://localhost/vulnerable-app/php/setup.php.
Access: http://localhost/vulnerable-app/php.

Flask

Open terminal in VS Code: cd C:\xampp\htdocs\vulnerable-app\python.
Install dependencies: pip install -r requirements.txt.
Initialize database: python database.py.
Start server: python app.py.
Access: http://localhost:5000.

Files

php/vulnerabilities/xss/stored.php: Stored XSS.
php/vulnerabilities/upload/upload.php: File upload.
report.pdf: Documentation.

