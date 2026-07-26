import re
import numpy as np
from scipy.sparse import hstack, csr_matrix

URL_RE = re.compile(r'https?://\S+|www\.\S+')
EMAIL_ADDRESS_RE = re.compile(r'[\w\.-]+@[\w\.-]+')
IP_URL_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
HTML_TAG_RE = re.compile(r'<.*?>')
SUSPICIOUS_KEYWORDS = [
    'urgent', 'verify', 'password', 'account suspended', 'click here', 'immediately',
    'confirm identity', 'security alert', 'winner', 'claim prize', 'limited time',
    'update payment', 'login now'
]


def extract_metadata_features(sender: str, subject: str, body: str) -> dict:
    """Extract metadata and structural features from the raw email."""
    text = f"{subject or ''} {body or ''}"
    url_matches = URL_RE.findall(text)
    url_count = len(url_matches)
    suspicious_url_count = sum(1 for url in url_matches if any(token in url.lower() for token in ['verify', 'login', 'update', 'secure', 'account', 'password', 'confirm']))
    email_address_count = len(EMAIL_ADDRESS_RE.findall(text))
    exclamation_count = text.count('!')
    question_count = text.count('?')
    digit_count = sum(char.isdigit() for char in text)
    uppercase_chars = sum(1 for char in text if char.isupper())
    total_chars = len(text) if len(text) > 0 else 1
    uppercase_ratio = uppercase_chars / total_chars
    body_length = len(body or '')
    subject_length = len(subject or '')
    suspicious_keyword_count = sum(text.lower().count(keyword) for keyword in SUSPICIOUS_KEYWORDS)
    html_tag_presence = 1 if HTML_TAG_RE.search(text) else 0
    ip_url_presence = 1 if IP_URL_RE.search(text) else 0
    urgency_count = sum(text.lower().count(phrase) for phrase in ['urgent', 'immediately', 'verify', 'login now', 'update payment'])

    return {
        'url_count': url_count,
        'suspicious_url_count': suspicious_url_count,
        'email_address_count': email_address_count,
        'exclamation_count': exclamation_count,
        'question_count': question_count,
        'digit_count': digit_count,
        'uppercase_ratio': round(uppercase_ratio, 4),
        'body_length': body_length,
        'subject_length': subject_length,
        'suspicious_keyword_count': suspicious_keyword_count,
        'html_tag_presence': html_tag_presence,
        'ip_url_presence': ip_url_presence,
        'urgency_keyword_count': urgency_count,
    }


def build_feature_matrix(text_features, metadata_features):
    """Combine sparse TF-IDF features with dense metadata features."""
    dense_features = np.array([
        [
            row['url_count'],
            row['suspicious_url_count'],
            row['email_address_count'],
            row['exclamation_count'],
            row['question_count'],
            row['digit_count'],
            row['uppercase_ratio'],
            row['body_length'],
            row['subject_length'],
            row['suspicious_keyword_count'],
            row['html_tag_presence'],
            row['ip_url_presence'],
            row['urgency_keyword_count'],
        ]
        for row in metadata_features
    ], dtype=np.float32)
    dense_matrix = csr_matrix(dense_features)
    return hstack([text_features, dense_matrix], format='csr')


def get_metadata_feature_names():
    return [
        'url_count',
        'suspicious_url_count',
        'email_address_count',
        'exclamation_count',
        'question_count',
        'digit_count',
        'uppercase_ratio',
        'body_length',
        'subject_length',
        'suspicious_keyword_count',
        'html_tag_presence',
        'ip_url_presence',
        'urgency_keyword_count',
    ]
