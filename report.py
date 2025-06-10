from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

c = canvas.Canvas("report.pdf", pagesize=letter)
c.drawString(100, 750, "Vulnerable Web App Report (Updated 11:56 PM IST, June 5, 2025)")
c.drawString(100, 730, "Content: Added SQLi query display, CSRF malicious example, severity ratings, OWASP refs")
c.drawString(100, 710, "Fixed sqlite3.ProgrammingError by using context managers for database connections")
c.drawString(100, 690, "UI/UX: Added active nav indicators, success/failure feedback, vulnerability descriptions, reset buttons")
c.drawString(100, 670, "Fixed FileNotFoundError by ensuring upload directory exists and adding file listing")
c.drawString(100, 650, "Updated navbar title to 'Vulnerable App' and placed above tabs")
c.drawString(100, 630, "Removed /comments-log hint from dashboard")
c.drawString(100, 610, "Fixed sqlite3.OperationalError by ensuring progress table is created in database.py")
c.drawString(100, 590, "Added new vulnerabilities: Broken Auth, IDOR, SSRF, XXE, Security Misconfigs, Deserialization")
c.drawString(100, 570, "Enhanced features: Progress tracking, hints, reset buttons, solution walkthroughs")
c.drawString(100, 550, "PHP: Stored XSS at /php/vulnerabilities/xss/stored.php")
c.drawString(100, 530, "Flask: Stored XSS at /comment")
c.drawString(100, 510, "Flags: flag{php_admin_access}, flag{php_hidden_flag}, flag{flask_api_vuln}, flag{flask_hidden_flag}, flag{file_based_comment_vuln}, flag{api_idor_vuln}")
c.drawString(100, 490, "Tools: Burp Suite, Wireshark, Nmap, Nessus")
c.save()