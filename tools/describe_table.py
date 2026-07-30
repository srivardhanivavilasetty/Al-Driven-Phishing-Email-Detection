import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import get_db_connection

conn = get_db_connection()
cur = conn.cursor()
cur.execute('SHOW COLUMNS FROM email_analysis')
cols = cur.fetchall()
print('COLUMNS in email_analysis:')
for c in cols:
    print(c)
cur.close(); conn.close()
