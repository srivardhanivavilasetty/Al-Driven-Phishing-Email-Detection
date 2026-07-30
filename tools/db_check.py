import sys, os, json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import get_db_connection

conn = get_db_connection()
cur = conn.cursor(dictionary=True)
cur.execute("SELECT id, email, name FROM users ORDER BY id DESC LIMIT 20")
users = cur.fetchall()
print('USERS:', json.dumps(users, default=str, indent=2))
cur.execute("SELECT id, user_id, sender, recipient, subject, prediction, confidence, created_at FROM email_analysis ORDER BY created_at DESC LIMIT 20")
rows = cur.fetchall()
print('EMAIL_ANALYSIS:', json.dumps(rows, default=str, indent=2))
cur.close(); conn.close()
