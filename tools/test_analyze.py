import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app, get_db_connection
from werkzeug.security import generate_password_hash

# Ensure test user exists
conn = get_db_connection()
cur = conn.cursor(dictionary=True)
email = 'testuser@example.com'
cur.execute('SELECT * FROM users WHERE email = %s', (email,))
user = cur.fetchone()
if not user:
    pw = generate_password_hash('testpass')
    cur.execute('INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, %s)', ('Test User', email, pw, 'user'))
    conn.commit()
    cur.execute('SELECT * FROM users WHERE email = %s', (email,))
    user = cur.fetchone()
user_id = user['id']
cur.close(); conn.close()

# Use test client to POST to /analyze with session
client = app.test_client()
with client.session_transaction() as sess:
    sess['user_id'] = user_id
    sess['user_name'] = user['name']
    sess['role'] = user['role']

resp = client.post('/analyze', data={
    'sender': 'alice@example.com',
    'recipient': 'bob@example.com',
    'subject': 'Test email',
    'email_body': 'This is a test email. Click http://malicious.example for details.',
    'date_time': '2026-07-30T10:00'
}, follow_redirects=True)

print('STATUS', resp.status_code)
text = resp.get_data(as_text=True)
print('LENGTH', len(text))
print('HAS_PREDICTION', 'Prediction' in text or 'PHISHING' in text or 'LEGITIMATE' in text)
open('tmp_response.html','w', encoding='utf-8').write(text)
print('WROTE tmp_response.html')
