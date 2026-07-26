import os
import json
import mysql.connector
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from ml.predict import predict_email

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']


def get_db_connection():
    return mysql.connector.connect(
        host=app.config['DB_HOST'],
        user=app.config['DB_USER'],
        password=app.config['DB_PASSWORD'],
        database=app.config['DB_NAME'],
        autocommit=True
    )


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Administrator privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def load_model_results():
    try:
        with open(os.path.join(os.path.dirname(__file__), 'models', 'model_results.json'), 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return None


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not name or not email or not password:
            flash('All fields are required.', 'warning')
            return render_template('register.html')

        password_hash = generate_password_hash(password)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, %s)',
                (name, email, password_hash, 'user')
            )
            conn.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('An account with that email already exists.', 'danger')
        except Exception:
            flash('Unable to create account, please try again later.', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not email or not password:
            flash('Email and password are required.', 'warning')
            return render_template('login.html')

        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            user = cursor.fetchone()
            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['role'] = user['role']
                flash('Login successful.', 'success')
                return redirect(url_for('dashboard'))
            flash('Invalid email or password.', 'danger')
        except Exception:
            flash('Unable to log in, please try again later.', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute('SELECT COUNT(*) AS total FROM email_analysis WHERE user_id = %s', (session['user_id'],))
        total_emails = cursor.fetchone()['total']
        cursor.execute('SELECT COUNT(*) AS total FROM email_analysis WHERE user_id = %s AND prediction = %s', (session['user_id'], 'PHISHING'))
        phishing_count = cursor.fetchone()['total']
        cursor.execute('SELECT COUNT(*) AS total FROM email_analysis WHERE user_id = %s AND prediction = %s', (session['user_id'], 'LEGITIMATE'))
        legitimate_count = cursor.fetchone()['total']
        cursor.execute(
            'SELECT sender, subject, prediction, confidence, risk_level, created_at FROM email_analysis WHERE user_id = %s ORDER BY created_at DESC LIMIT 5',
            (session['user_id'],)
        )
        recent = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    return render_template('dashboard.html', total_emails=total_emails,
                           phishing_count=phishing_count,
                           legitimate_count=legitimate_count,
                           recent=recent)


@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    if request.method == 'POST':
        sender = request.form.get('sender', '').strip()
        subject = request.form.get('subject', '').strip()
        email_body = request.form.get('email_body', '').strip()
        if not sender or not subject or not email_body:
            flash('All fields are required to analyze an email.', 'warning')
            return render_template('analyze.html', sender=sender, subject=subject, email_body=email_body)

        try:
            result = predict_email(sender, subject, email_body)
        except FileNotFoundError as ex:
            flash(str(ex), 'danger')
            return render_template('analyze.html', sender=sender, subject=subject, email_body=email_body)
        except Exception:
            flash('Unable to analyze email at this time.', 'danger')
            return render_template('analyze.html', sender=sender, subject=subject, email_body=email_body)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO email_analysis (user_id, sender, subject, email_body, prediction, confidence, risk_score, risk_level, url_count, suspicious_keyword_count, warning_indicators) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                (
                    session['user_id'], sender, subject, email_body,
                    result['prediction'], result['confidence'], result['risk_score'],
                    result['risk_level'], result['extracted_features']['url_count'],
                    result['extracted_features']['suspicious_keyword_count'],
                    ', '.join(result['warning_indicators'])
                )
            )
            conn.commit()
        except Exception:
            flash('Analysis result could not be saved to history.', 'warning')
        finally:
            cursor.close()
            conn.close()

        return render_template('result.html', result=result, sender=sender, subject=subject, email_body=email_body)

    return render_template('analyze.html')


@app.route('/result')
@login_required
def result():
    flash('Please analyze an email first.', 'info')
    return redirect(url_for('analyze'))


@app.route('/history')
@login_required
def history():
    search_query = request.args.get('search', '').strip()
    filter_prediction = request.args.get('filter', '').strip()
    sql = 'SELECT id, sender, subject, prediction, confidence, risk_level, created_at FROM email_analysis WHERE user_id = %s'
    params = [session['user_id']]
    if search_query:
        sql += ' AND (sender LIKE %s OR subject LIKE %s OR warning_indicators LIKE %s)'
        like_value = f'%{search_query}%'
        params.extend([like_value, like_value, like_value])
    if filter_prediction in ['PHISHING', 'LEGITIMATE']:
        sql += ' AND prediction = %s'
        params.append(filter_prediction)
    sql += ' ORDER BY created_at DESC'

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(sql, tuple(params))
        records = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    return render_template('history.html', records=records, search_query=search_query, filter_prediction=filter_prediction)


@app.route('/delete-history/<int:record_id>', methods=['POST'])
@login_required
def delete_history(record_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM email_analysis WHERE id = %s AND user_id = %s', (record_id, session['user_id']))
        if cursor.rowcount == 0:
            flash('No record deleted. It may not belong to you.', 'warning')
        else:
            flash('History item deleted.', 'success')
        conn.commit()
    except Exception:
        flash('Unable to delete history item.', 'danger')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('history'))


@app.route('/performance')
@login_required
def performance():
    model_results = load_model_results()
    return render_template('performance.html', model_results=model_results)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('SELECT COUNT(*) AS total FROM users')
        total_users = cursor.fetchone()['total']
        cursor.execute('SELECT COUNT(*) AS total FROM email_analysis')
        total_scans = cursor.fetchone()['total']
        cursor.execute('SELECT COUNT(*) AS total FROM email_analysis WHERE prediction = %s', ('PHISHING',))
        total_phishing = cursor.fetchone()['total']
        cursor.execute('SELECT COUNT(*) AS total FROM email_analysis WHERE prediction = %s', ('LEGITIMATE',))
        total_legitimate = cursor.fetchone()['total']
        cursor.execute('SELECT sender, subject, prediction, risk_level, created_at FROM email_analysis ORDER BY created_at DESC LIMIT 5')
        recent = cursor.fetchall()
        model_results = load_model_results()
    finally:
        cursor.close()
        conn.close()

    return render_template('admin_dashboard.html', total_users=total_users,
                           total_scans=total_scans,
                           total_phishing=total_phishing,
                           total_legitimate=total_legitimate,
                           recent=recent,
                           model_results=model_results)


@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC')
        users = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()
    return render_template('manage_users.html', users=users)


@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if session.get('user_id') == user_id:
        flash('You cannot delete your own active administrator account.', 'warning')
        return redirect(url_for('manage_users'))
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        flash('User deleted successfully.', 'success')
    except Exception:
        flash('Unable to delete user.', 'danger')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('manage_users'))


if __name__ == '__main__':
    app.run(debug=True)
