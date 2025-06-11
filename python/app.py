from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, IntegerField, SelectField
from wtforms.validators import DataRequired, NumberRange
import sqlite3
import os
import xml.etree.ElementTree as ET
import pickle
import base64
import requests
import urllib.parse
import shutil
import hashlib
import html
import time

app = Flask(__name__)
app.secret_key = 'secure-secret-key-12345'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
csrf = CSRFProtect(app)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

app.jinja_env.globals.update(html=html)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[DataRequired()])

class TransferForm(FlaskForm):
    amount = IntegerField('Amount', validators=[DataRequired(), NumberRange(min=1)])

class SSRFForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired()])

class XXEForm(FlaskForm):
    xml_data = TextAreaField('XML Data', validators=[DataRequired()])

class DeserializationForm(FlaskForm):
    data = StringField('Data', validators=[DataRequired()])

class ReflectedXSSForm(FlaskForm):
    search = StringField('Search', validators=[DataRequired()])

class ReportForm(FlaskForm):
    challenge = SelectField('Challenge', choices=[
        ('login', 'Login Weak Auth'),
        ('xss', 'Comments XSS'),
        ('csrf', 'Transfer CSRF'),
        ('upload', 'File Upload'),
        ('idor', 'Profile IDOR'),
        ('ssrf', 'SSRF'),
        ('xxe', 'XXE'),
        ('deserialize', 'Insecure Deserialization'),
        ('reflected_xss', 'Reflected XSS'),
        ('broken_auth', 'Broken Authentication'),
        ('blind_sqli', 'Blind SQLi'),
        ('dom_xss', 'DOM-based XSS'),
        ('ssti', 'Server-Side Template Injection'),
        ('csrf_page', 'Cross-Site Request Forgery')
    ], validators=[DataRequired()])
    writeup = TextAreaField('Write-Up', validators=[DataRequired()])

class BlindSQLiForm(FlaskForm):
    user_id = IntegerField('User ID', validators=[DataRequired()])

class SSTIForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])

class CSRFForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database with a reports table
with get_db_connection() as conn:
    conn.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        challenge TEXT NOT NULL,
        writeup TEXT NOT NULL
    )''')
    conn.commit()

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
    'blind_sqli': ('Hard', 40),
    'dom_xss': ('Medium', 20),
    'ssti': ('Advanced', 40),
    'csrf_page': ('Medium', 20),
}

def update_progress(user, challenge):
    with get_db_connection() as conn:
        existing = conn.execute("SELECT * FROM progress WHERE user = ? AND challenge = ?", (user, challenge)).fetchone()
        if not existing:
            difficulty, score = DIFFICULTY_SCORES.get(challenge, ('Easy', 10))
            conn.execute("INSERT INTO progress (user, challenge, score) VALUES (?, ?, ?)", (user, challenge, score))
            conn.commit()

def get_progress(user):
    with get_db_connection() as conn:
        progress = conn.execute("SELECT challenge, score FROM progress WHERE user = ?", (user,)).fetchall()
    completed_challenges = [row['challenge'] for row in progress]
    total_score = sum(row['score'] for row in progress)
    total_possible_score = sum(score for _, score in DIFFICULTY_SCORES.values())
    completion_percentage = (len(completed_challenges) / len(DIFFICULTY_SCORES)) * 100 if DIFFICULTY_SCORES else 0
    return completed_challenges, total_score, total_possible_score, completion_percentage

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    executed_query = None
    debug_mode = request.args.get('debug', 'off') == 'on'
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        executed_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        with get_db_connection() as conn:
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            user = conn.execute(query).fetchone()
        if user:
            session['user'] = username
            session['session_id'] = os.urandom(16).hex()
            update_progress(username, 'login')
            return redirect(url_for('dashboard'))
        return render_template('login.html', form=form, error="Login failed!", executed_query=executed_query if debug_mode else None, debug_mode=debug_mode)
    return render_template('login.html', form=form, executed_query=executed_query if debug_mode else None, debug_mode=debug_mode)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    progress, total_score, total_possible_score, completion_percentage = get_progress(session['user'])
    return render_template('dashboard.html', user=session['user'], progress=progress, total_score=total_score, total_possible_score=total_possible_score, completion_percentage=completion_percentage)

@app.route('/getting-started')
def getting_started():
    return render_template('getting_started.html')

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if 'user' not in session:
        return redirect(url_for('login'))
    form = CommentForm()
    error = None
    success = None
    with get_db_connection() as conn:
        if form.validate_on_submit():
            comment_text = form.comment.data
            if len(comment_text) < 3:
                error = "Comment must be at least 3 characters long (server-side validation)"
            else:
                if "<script>" in comment_text.lower():
                    success = "Exploit Successful! XSS payload detected."
                    update_progress(session['user'], 'xss')
                else:
                    error = "No XSS payload detected. Try again!"
                conn.execute("INSERT INTO comments (comment) VALUES (?)", (comment_text,))
                conn.commit()
        comments = conn.execute("SELECT comment FROM comments").fetchall()
    return render_template('comment.html', form=form, comments=comments, success=success, error=error)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user' not in session:
        return redirect(url_for('login'))
    form = TransferForm()
    error = None
    success = None
    amount = None

    if request.method == 'POST':
        if form.validate_on_submit():
            amount = form.amount.data
    elif request.method == 'GET':
        amount = request.args.get('amount', type=int)
        if amount is None or amount < 1:
            error = "Invalid amount provided in GET request."
            return render_template('transfer.html', form=form, success=success, error=error)

    if amount:
        referer = request.headers.get('Referer', '')
        if 'malicious-site' in referer or 'localhost:5000/malicious-csrf-example' in referer:
            success = "Exploit Successful! CSRF attack simulated."
            update_progress(session['user'], 'csrf')
        else:
            error = "No CSRF exploit detected. Simulate a malicious request!"
        return render_template('transfer.html', form=form, message=f"Transferred ${amount} successfully!", success=success, error=error)

    return render_template('transfer.html', form=form, success=success, error=error)

@app.route('/malicious-csrf-example')
def malicious_csrf_example():
    return render_template('malicious_csrf_example.html')

@csrf.exempt
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    error = None
    success = None
    if request.method == 'POST':
        if 'file' not in request.files:
            error = "No file uploaded"
        else:
            file = request.files['file']
            if file.filename == '':
                error = "No file selected"
            else:
                filename = os.path.basename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                if filename.endswith('.php'):
                    success = "Exploit Successful! Malicious file uploaded."
                    update_progress(session['user'], 'upload')
                else:
                    error = "No malicious file detected. Try uploading a .php file!"
                files = os.listdir(app.config['UPLOAD_FOLDER'])
        return render_template('upload.html', message=f"File {filename} uploaded successfully!" if not error else None, success=success, error=error, files=files)
    return render_template('upload.html', success=success, error=error, files=files)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        return "File not found", 404

@app.route('/profile/<int:user_id>')
def profile(user_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        error = None
        success = None
        if user:
            logged_in_user = conn.execute("SELECT id FROM users WHERE username = ?", (session['user'],)).fetchone()
            if logged_in_user and user_id != logged_in_user['id']:
                success = "Exploit Successful! Accessed another user's profile."
                update_progress(session['user'], 'idor')
            else:
                error = "No IDOR exploit detected. Try accessing another user's profile!"
            return render_template('profile.html', user=user, success=success, error=error)
        return "User not found", 404

@app.route('/ssrf', methods=['GET', 'POST'])
def ssrf():
    if 'user' not in session:
        return redirect(url_for('login'))
    form = SSRFForm()
    error = None
    success = None
    content = None
    if form.validate_on_submit():
        url = form.url.data
        try:
            if 'localhost' in url or '127.0.0.1' in url:
                success = "Exploit Successful! Accessed internal resource."
                update_progress(session['user'], 'ssrf')
                content = "Internal Server Data: CTF{ssrf_success}"
            else:
                error = "No SSRF exploit detected. Try accessing an internal resource!"
                response = requests.get(url, timeout=5)
                content = response.text
        except Exception as e:
            error = str(e)
        return render_template('ssrf.html', form=form, content=content, success=success, error=error)
    return render_template('ssrf.html', form=form, error=error)

@app.route('/xxe', methods=['GET', 'POST'])
def xxe():
    if 'user' not in session:
        return redirect(url_for('login'))
    form = XXEForm()
    error = None
    success = None
    result = None
    if form.validate_on_submit():
        xml_data = form.xml_data.data
        try:
            parser = ET.XMLParser(resolve_entities=True)
            root = ET.fromstring(xml_data, parser=parser)
            result = ET.tostring(root, encoding='unicode')
            if "<!ENTITY" in xml_data:
                success = "Exploit Successful! XXE payload detected."
                update_progress(session['user'], 'xxe')
            else:
                error = "No XXE payload detected. Try using an external entity!"
        except Exception as e:
            error = str(e)
        return render_template('xxe.html', form=form, result=result, success=success, error=error)
    return render_template('xxe.html', form=form)

@app.route('/deserialize', methods=['GET', 'POST'])
def deserialize():
    if 'user' not in session:
        return redirect(url_for('login'))
    form = DeserializationForm()
    error = None
    success = None
    result = None
    if form.validate_on_submit():
        data = form.data.data
        try:
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)
            result = str(obj)
            if "system" in str(obj).lower() or "exec" in str(obj).lower():
                success = "Exploit Successful! Malicious deserialization payload detected."
                update_progress(session['user'], 'deserialize')
            else:
                error = "No malicious payload detected. Try a harmful pickle object!"
        except Exception as e:
            error = str(e)
        return render_template('deserialize.html', form=form, result=result, success=success, error=error)
    return render_template('deserialize.html', form=form)

@app.route('/reflected-xss', methods=['GET', 'POST'])
def reflected_xss():
    if 'user' not in session:
        return redirect(url_for('login'))
    search = request.args.get('search', '')
    return render_template('reflected_xss.html', search=search)

@app.route('/broken-auth', methods=['GET', 'POST'])
def broken_auth():
    if 'user' not in session:
        return redirect(url_for('login'))
    form = LoginForm()
    error = None
    success = None
    if form.validate_on_submit():
        password = form.password.data
        if len(password) < 4:
            error = "Password too short! (vulnerable check)"
        else:
            success = "Weak authentication detected! Session ID: " + session['session_id']
            update_progress(session['user'], 'broken_auth')
    return render_template('broken_auth.html', form=form, success=success, error=error)

@app.route('/blind-sqli', methods=['GET', 'POST'])
def blind_sqli():
    if 'user' not in session:
        return redirect(url_for('login'))
    form = BlindSQLiForm()
    error = None
    success = None
    result = None
    if form.validate_on_submit():
        user_id = form.user_id.data
        try:
            with get_db_connection() as conn:
                # Vulnerable query for blind SQLi (time-based)
                query = f"SELECT * FROM users WHERE id = {user_id}"
                start_time = time.time()
                user = conn.execute(query).fetchone()
                elapsed_time = time.time() - start_time
                if elapsed_time > 2:  # Simulated delay for blind SQLi detection
                    success = "Exploit Successful! Blind SQLi detected via time delay."
                    update_progress(session['user'], 'blind_sqli')
                elif user:
                    result = f"User found: {user['username']}"
                else:
                    error = "No Blind SQLi detected. Try a time-based attack!"
        except Exception as e:
            error = str(e)
        return render_template('blind_sqli.html', form=form, result=result, success=success, error=error)
    return render_template('blind_sqli.html', form=form)

@app.route('/dom-xss')
def dom_xss():
    if 'user' not in session:
        return redirect(url_for('login'))
    success = None
    ctf_flag = None
    hash = request.args.get('hash', '')
    if 'message' in hash and '<script>alert' in hash:
        success = "Exploit Successful! DOM XSS payload detected."
        ctf_flag = "CTF{dom_xss_success}"
        update_progress(session['user'], 'dom_xss')
    return render_template('dom_xss.html', success=success, ctf_flag=ctf_flag)

@app.route('/ssti', methods=['GET', 'POST'])
def ssti():
    if 'user' not in session:
        return redirect(url_for('login'))
    form = SSTIForm()
    name = None
    if form.validate_on_submit():
        name = form.name.data
        if '{{' in name and '}}' in name:
            update_progress(session['user'], 'ssti')
    return render_template('ssti.html', form=form, name=name)

@csrf.exempt
@app.route('/csrf', methods=['GET', 'POST'])
def csrf_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    form = CSRFForm()
    email = ''
    success = False
    if form.validate_on_submit():
        email = form.email.data
        success = True
        update_progress(session['user'], 'csrf_page')
    return render_template('csrf.html', form=form, email=email, success=success)

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user' not in session:
        return redirect(url_for('login'))
    form = ReportForm()
    error = None
    success = None
    with get_db_connection() as conn:
        if form.validate_on_submit():
            challenge = form.challenge.data
            writeup = form.writeup.data
            conn.execute("INSERT INTO reports (username, challenge, writeup) VALUES (?, ?, ?)",
                        (session['user'], challenge, writeup))
            conn.commit()
            success = "Report submitted successfully!"
        reports = conn.execute("SELECT * FROM reports").fetchall()
    return render_template('report.html', form=form, reports=reports, success=success, error=error)

@app.route('/progress')
def progress():
    if 'user' not in session:
        return redirect(url_for('login'))
    completed_challenges, total_score, total_possible_score, completion_percentage = get_progress(session['user'])
    return render_template('progress.html', completed=completed_challenges, total_score=total_score,
                         total_possible_score=total_possible_score, completion_percentage=completion_percentage)

@app.route('/logout')
def logout():
    session.clear()
    return render_template('logout.html')

@app.route('/api/user/<int:user_id>')
def api_user(user_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user:
            update_progress(session['user'], 'api')
            return jsonify({"id": user['id'], "username": user['username'], "flag": "flag{api_idor_vuln}"})
        return jsonify({"error": "User not found"}), 404

@app.route('/api/flag')
def api_flag():
    return jsonify({"flag": "flag{flask_api_vuln}"})

@app.route('/comments-log')
def comments_log():
    try:
        with open('static/comments.txt', 'r') as f:
            content = f.read()
        return content
    except FileNotFoundError:
        return "Comments log not found.", 404

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/reset/<page>', methods=['POST'])
def reset(page):
    if 'user' not in session:
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        if page == 'comment':
            conn.execute("DELETE FROM comments")
        elif page == 'progress':
            conn.execute("DELETE FROM progress WHERE user = ?", (session['user'],))
        elif page == 'reports':
            conn.execute("DELETE FROM reports WHERE username = ?", (session['user'],))
        elif page == 'upload':
            if os.path.exists(app.config['UPLOAD_FOLDER']):
                shutil.rmtree(app.config['UPLOAD_FOLDER'])
                os.makedirs(app.config['UPLOAD_FOLDER'])
            conn.execute("DELETE FROM progress WHERE user = ? AND challenge = ?", (session['user'], 'upload'))
        elif page in ['login', 'csrf', 'idor', 'ssrf', 'xxe', 'deserialize', 'reflected_xss', 'broken_auth', 'blind_sqli', 'dom_xss', 'ssti', 'csrf_page']:
            conn.execute("DELETE FROM progress WHERE user = ? AND challenge = ?", (session['user'], page))
        conn.commit()
    return redirect(url_for('dashboard'))
