import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import get_db_connection

conn = get_db_connection()
cur = conn.cursor()
# Check if recipient exists
cur.execute("SHOW COLUMNS FROM email_analysis LIKE 'recipient'")
if cur.fetchone():
    print('Column recipient already exists')
else:
    print('Adding recipient column...')
    cur.execute("ALTER TABLE email_analysis ADD COLUMN recipient VARCHAR(255) NOT NULL AFTER sender")
    conn.commit()
    print('Added recipient column')
cur.close(); conn.close()
