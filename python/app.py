from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory, flash, make_response
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, IntegerField, SelectField
from wtforms.validators import DataRequired, NumberRange, Email
from database import init_db, get_db_connection, update_progress, log_action, get_progress, DIFFICULTY_SCORES
from wtforms import StringField, SubmitField
from datetime import timedelta
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
from datetime import datetime



app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure-secret-key-12345'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
csrf = CSRFProtect(app)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

app.jinja_env.globals.update(html=html)

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Email

class SettingsForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'placeholder': 'Enter your email'})
    action = StringField('Action', default='update', render_kw={'type': 'hidden'})
    submit = SubmitField('Update Settings')
class CommentSearchForm(FlaskForm):
    search = StringField('Search Comments', validators=[DataRequired()])
    submit = SubmitField('Search')

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


challenge_display_names = {
    'login': 'Login Weak Auth',
    'xss': 'Comments XSS',
    'csrf': 'CSRF Transfer Attack',
    'upload': 'File Upload',
    'idor': 'Profile IDOR',
    'ssrf': 'SSRF',
    'xxe': 'XXE',
    'deserialize': 'Insecure Deserialization',
    'reflected_xss': 'Reflected XSS',
    'broken_auth': 'Broken Authentication',
    'dom_xss': 'DOM-based XSS',
    'ssti': 'Server-Side Template Injection',
    'csrf_page': 'CSRF Settings Exploit'
}


class ReportForm(FlaskForm):
    challenge = SelectField('Challenge', choices=[
        ('login', 'Login Weak Auth'),
        ('xss', 'Comments XSS'),
        ('csrf', 'CSRF Transfer Attack'),
        ('upload', 'File Upload'),
        ('idor', 'Profile IDOR'),
        ('ssrf', 'SSRF'),
        ('xxe', 'XXE'),
        ('deserialize', 'Insecure Deserialization'),
        ('reflected_xss', 'Reflected XSS'),
        ('broken_auth', 'Broken Authentication'),
        ('dom_xss', 'DOM-based XSS'),
        ('ssti', 'Server-Side Template Injection'),
        ('csrf_page', 'CSRF Settings Exploit')
    ], validators=[DataRequired()])
    writeup = TextAreaField('Write-Up', validators=[DataRequired()])
    submit = SubmitField('Submit Report')
    
class BlindSQLiForm(FlaskForm):
    user_id = IntegerField('User ID', validators=[DataRequired()])

class SSTIForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])

class CSRFForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])

def get_comments():
    with get_db_connection() as conn:
        comments = conn.execute("SELECT username, content, date_posted FROM comments").fetchall()
    return comments

try:
    with app.app_context():
        init_db()
except Exception as e:
    print(f"Failed to initialize database: {e}")
    raise

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


from datetime import datetime

def log_action(user, action, details):
    timestamp = "2025-06-17 08:25:00"  # Hardcoding for consistency with current date and time
    with get_db_connection() as conn:
        conn.execute("INSERT INTO logs (timestamp, user, action, details) VALUES (?, ?, ?, ?)",
                     (timestamp, user, action, details))
        conn.commit()
    
@app.route('/', methods=['GET', 'POST'])
def login():
    init_db()  # Ensure the database is initialized
    form = LoginForm()
    error = None
    executed_query = None

    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            # Intentionally vulnerable SQL query
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            executed_query = query  # For displaying the query in template
            print(f"Executing: {query}")

            with get_db_connection() as conn:
                try:
                    # Special handling for the SQL injection case
                    if "OR '1'='1'" in query.upper():
                        # Fix the syntax by properly closing the quotes
                        fixed_query = query.replace("OR '1'='1'", "OR '1'='1' --")
                        user = conn.execute(fixed_query).fetchone()
                    else:
                        user = conn.execute(query).fetchone()

                    if user:
                        # Set session data
                        session['user'] = user['username']
                        session['user_id'] = user['username']  # Using username as ID is insecure
                        session['is_admin'] = True if user['username'] == 'admin' else False
                        
                        # Predictable session token generation (vulnerable)
                        session['token'] = f"SESSION_{user['username'].lower()}_12345"
                        
                        # Predictable session_id for broken_auth vulnerability
                        # Using a simple, guessable format: username + fixed string
                        predictable_session_id = f"{user['username'].lower()}_auth_123"
                        session['session_id'] = predictable_session_id
                        
                        # Set the vulnerable session_id in a cookie
                        response = make_response(redirect(url_for('dashboard')))
                        response.set_cookie('vuln_session_id', predictable_session_id)
                        
                        log_action(user['username'], "Login", "Logged in via SQLi")
                        update_progress(user['username'], 'login')
                        return response
                    else:
                        error = "Invalid username or password"
                except Exception as e:
                    error = f"Database error: {str(e)}"
                    print(f"Error: {str(e)}")

    return render_template('login.html', form=form, error=error, executed_query=executed_query)
    
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        progress = conn.execute("SELECT * FROM progress WHERE user = ?", (session['user'],)).fetchall()
        logs = conn.execute("SELECT * FROM logs WHERE user = ? ORDER BY timestamp DESC LIMIT 5", (session['user'],)).fetchall()
    total_score = sum(row['score'] for row in progress)
    total_challenges = len(DIFFICULTY_SCORES)
    completed_challenges = len(progress)
    completion_percentage = (completed_challenges / total_challenges * 100) if total_challenges > 0 else 0
    max_score = sum(score for _, score in DIFFICULTY_SCORES.values())
    return render_template('dashboard.html', progress=progress, total_score=total_score, max_score=max_score,
                         completed_challenges=completed_challenges, total_challenges=total_challenges,
                         completion_percentage=completion_percentage, logs=logs, challenge_display_names=challenge_display_names)

@app.route('/getting-started')
def getting_started():
    if 'user' not in session:
        return redirect(url_for('login'))
    update_progress(session['user'], 'getting_started')
    return render_template('getting_started.html')


@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    form = CommentSearchForm()
    comments = []
    success = None
    error = None
    ctf_flag = None
    
    with get_db_connection() as conn:
        if request.method == 'POST' and form.validate_on_submit():
            search_term = form.search.data
            try:
                query = f"SELECT * FROM comments WHERE content LIKE '%{search_term}%'"
                cursor = conn.cursor()
                cursor.execute(query)
                comments = cursor.fetchall()
                if "' OR '1'='1" in search_term:
                    update_progress(session['user'], 'xss')
                    success = "SQL Injection challenge completed!"
                    ctf_flag = "FLAG{SQL_INJECTION_SUCCESS}"
            except Exception as e:
                error = f"Error executing query: {str(e)}"
        else:
            comments = get_comments()
    
    return render_template('comment.html', form=form, comments=comments, success=success, error=error, ctf_flag=ctf_flag)


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
        print(f"Referer: {referer}")
        if request.method == 'GET':
            print(f"CSRF exploit detected for user {session['user']}")
            success = "Exploit Successful! CSRF attack simulated."
            update_progress(session['user'], 'csrf')
            log_action(session['user'], "CSRF Success (Transfer)", f"CSRF exploit completed for transfer, Amount: {amount}")
        else:
            error = "No CSRF exploit detected. Simulate a malicious request!"
            log_action(session['user'], "CSRF Failed (Transfer)", "CSRF exploit attempt failed")
        return render_template('transfer.html', form=form, message=f"Transferred ${amount} successfully!", success=success, error=error)

    return render_template('transfer.html', form=form, success=success, error=error)

@app.route('/csrf-exploit')
def csrf_exploit():
    return render_template('csrf_exploit.html')

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
        print(f"Session user: {session['user']}")
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        print(f"Target user: {user}")
        error = None
        success = None
        ctf_flag = None
        if user:
            logged_in_user = conn.execute("SELECT id FROM users WHERE username = ?", (session['user'],)).fetchone()
            print(f"Logged-in user: {logged_in_user}")
            if logged_in_user is None:
                flash('Logged-in user not found. Please log in again.', 'error')
                return redirect(url_for('login'))
            print(f"Comparing user_id={user_id} with logged_in_user['id']={logged_in_user['id']}")
            if user_id != logged_in_user['id']:
                success = "Successfully exploited IDOR vulnerability!"
                ctf_flag = "CTF{idor_success}"
                existing = conn.execute("SELECT * FROM progress WHERE user = ? AND challenge = ?", (session['user'], 'idor')).fetchone()
                if not existing:
                    update_progress(session['user'], 'idor')
                    print("IDOR progress updated")
                else:
                    print("IDOR progress already recorded")
            else:
                error = "No IDOR exploit detected. Try accessing another user's profile!"
            profile_data = f"Profile Data for User ID {user_id}\nSensitive Info: [REDACTED]"
            return render_template('profile.html', user=user, success=success, error=error, ctf_flag=ctf_flag, profile_data=profile_data)
        flash('User not found.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/ssrf', methods=['GET', 'POST'])
def ssrf():
    if 'user' not in session:
        return redirect(url_for('login'))
    form = SSRFForm()
    result = None
    success = None
    ctf_flag = None
    if form.validate_on_submit():
        url = form.url.data
        try:
            response = requests.get(url, timeout=2)
            result = response.text[:500]
        except requests.exceptions.RequestException as e:
            result = f"Error fetching URL: {str(e)}"
        if 'localhost:5000' in url.lower():
            success = "Exploit Successful! SSRF payload detected."
            ctf_flag = "CTF{ssrf_success}"
            update_progress(session['user'], 'ssrf')
        return render_template('ssrf.html', form=form, result=result, success=success, ctf_flag=ctf_flag)
    return render_template('ssrf.html', form=form)

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
        if "<!ENTITY" in xml_data:
            success = "Exploit Successful! XXE payload detected."
            update_progress(session['user'], 'xxe')
            try:
                root = ET.fromstring(xml_data)
                result = ET.tostring(root, encoding='unicode')
            except Exception as e:
                result = "XML parsing failed (expected due to XXE payload)."
                error = str(e)
        else:
            error = "No XXE payload detected. Try using an external entity!"
            try:
                root = ET.fromstring(xml_data)
                result = ET.tostring(root, encoding='unicode')
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

@app.route('/reflected-xss', methods=['GET'])
def reflected_xss():
    if 'user' not in session:
        return redirect(url_for('login'))
    query = request.args.get('query', '')
    error = None
    success = None
    if query:
        if "<script>" in query:
            success = "Exploit Successful! Reflected XSS payload detected."
            update_progress(session['user'], 'reflected_xss')
        else:
            error = "No XSS payload detected. Try including a script tag!"
    return render_template('reflected_xss.html', query=query, success=success, error=error)

@app.route('/broken-auth', methods=['GET', 'POST'])
def broken_auth():
    if 'user' not in session:
        return redirect(url_for('login'))
    error = None
    success = None
    ctf_flag = None
    if request.method == 'POST':
        submitted_token = request.form.get('session_token')
        if submitted_token == session.get('session_id'):
            success = f"🎉 Exploit successful! Session ID matched: {submitted_token}"
            ctf_flag = "CTF{broken_auth_success}"
            update_progress(session['user'], 'broken_auth')
        else:
            error = "❌ Invalid session ID."
    return render_template('broken_auth.html', success=success, error=error, ctf_flag=ctf_flag)

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
                query = f"SELECT * FROM users WHERE id = {user_id}"
                start_time = time.time()
                user = conn.execute(query).fetchone()
                elapsed_time = time.time() - start_time
                if elapsed_time > 2:
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
        log_action(session['user'], "DOM XSS Attempt", f"Payload: {hash}")
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
    success = None
    ctf_flag = None
    if form.validate_on_submit():
        name = form.name.data
        if '{{' in name and '}}' in name:
            success = "Exploit Successful! SSTI payload detected."
            ctf_flag = "CTF{ssti_success}"
            update_progress(session['user'], 'ssti')
    return render_template('ssti.html', form=form, name=name, success=success, ctf_flag=ctf_flag)


@csrf.exempt
@app.route('/csrf', methods=['GET', 'POST'])
def csrf_page():
    if 'user' not in session:
        return redirect(url_for('login'))

    form = CSRFForm()
    email = ''
    success = False

    validated = form.validate_on_submit()
    print("Form submitted?", validated)
    print("Form data:", form.data)
    print("Form errors:", form.errors)

    if validated:
        email = form.email.data
        success = True
        update_progress(session['user'], 'csrf_page')

    return render_template('csrf.html', form=form, email=email, success=success)


def log_action(user, action, details):
    timestamp = "2025-06-17 09:21:00"  # Updated to current time
    with get_db_connection() as conn:
        conn.execute("INSERT INTO logs (timestamp, user, action, details) VALUES (?, ?, ?, ?)",
                     (timestamp, user, action, details))
        conn.commit()

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user' not in session:
        return redirect(url_for('login'))
    form = ReportForm()
    success = None
    error = None
    current_time = "2025-06-17 09:36:00"  # Current time
    if request.method == 'POST':
        if form.validate_on_submit():
            challenge = form.challenge.data
            writeup = form.writeup.data
            # Validate that the challenge exists
            if challenge not in DIFFICULTY_SCORES:
                error = "Invalid challenge selected."
            else:
                # Store the report
                with get_db_connection() as conn:
                    conn.execute("INSERT INTO reports (timestamp, user, challenge, writeup) VALUES (?, ?, ?, ?)",
                                 (current_time, session['user'], challenge, writeup))
                    conn.commit()
                log_action(session['user'], "Report Submitted", f"Submitted report for challenge: {challenge}")
                success = "Report submitted successfully!"
        else:
            error = "Please fill out all required fields."
    return render_template('report.html', form=form, success=success, error=error, current_time=current_time,
                        challenge_display_names=challenge_display_names)

@app.route('/progress')
def progress():
    if 'user' not in session:
        return redirect(url_for('login'))
    completed_challenges, total_score, total_possible_score = get_progress(session['user'])
    return render_template('progress.html', completed=completed_challenges, total_score=total_score,
                         total_possible_score=total_possible_score)

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
            log_action(session['user'], "BOLA Attempt", f"Accessed user ID: {user_id}")
            logged_in_user = conn.execute("SELECT id FROM users WHERE username = ?", (session['user'],)).fetchone()
            if logged_in_user and user_id != logged_in_user['id']:
                update_progress(session['user'], 'bola')
                return jsonify({"id": user['id'], "username": user['username'], "email": user['email'], "role": user['role'], "flag": "CTF{bola_success}"})
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
        elif page in ['login', 'csrf', 'idor', 'ssrf', 'xxe', 'deserialize', 'reflected_xss', 'broken_auth', 'blind_sqli', 'dom_xss', 'ssti', 'csrf_page', 'bola', 'sql_injection']:
            conn.execute("DELETE FROM progress WHERE user = ? AND challenge = ?", (session['user'], page))
        conn.commit()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)