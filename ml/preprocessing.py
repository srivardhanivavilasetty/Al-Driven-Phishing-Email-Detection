import re
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize

nltk_packages = {
    'punkt': 'tokenizers/punkt',
    'stopwords': 'corpora/stopwords',
    'wordnet': 'corpora/wordnet',
    'omw-1.4': 'corpora/omw-1.4'
}
for package, resource_path in nltk_packages.items():
    try:
        nltk.data.find(resource_path)
    except LookupError:
        nltk.download(package)

STOPWORDS = set(stopwords.words('english'))
LEMMATIZER = WordNetLemmatizer()

HTML_TAG_RE = re.compile(r'<.*?>')
URL_RE = re.compile(r'https?://\S+|www\.\S+')
EMAIL_ADDRESS_RE = re.compile(r'[\w\.-]+@[\w\.-]+')
NON_ALPHANUMERIC_RE = re.compile(r'[^a-zA-Z0-9\s]')
MULTI_WHITESPACE_RE = re.compile(r'\s+')

SUSPICIOUS_PHRASES = [
    'urgent', 'verify', 'password', 'account suspended', 'click here', 'immediately',
    'confirm identity', 'security alert', 'winner', 'claim prize', 'limited time',
    'update payment', 'login now'
]


def clean_text(subject: str, body: str) -> str:
    """Clean and normalize email text for NLP."""
    text = f"{subject or ''} {body or ''}"
    text = text.lower()
    text = HTML_TAG_RE.sub(' ', text)
    text = NON_ALPHANUMERIC_RE.sub(' ', text)
    text = MULTI_WHITESPACE_RE.sub(' ', text).strip()
    tokens = word_tokenize(text)
    tokens = [token for token in tokens if token not in STOPWORDS and len(token) > 1]
    tokens = [LEMMATIZER.lemmatize(token) for token in tokens]
    return ' '.join(tokens)


def prepare_dataframe(df):
    """Prepare a dataframe by cleaning text and normalizing labels."""
    df = df.copy()
    df['sender'] = df['sender'].fillna('unknown@unknown.com')
    df['subject'] = df['subject'].fillna('')
    df['body'] = df['body'].fillna('')
    df['clean_text'] = df.apply(lambda row: clean_text(row['subject'], row['body']), axis=1)

    def normalize_label(label):
        if isinstance(label, str):
            label_lower = label.strip().lower()
            if label_lower in ['phishing', '1', 'true', 'yes']:
                return 1
            if label_lower in ['legitimate', '0', 'false', 'no', 'ham']:
                return 0
        try:
            return int(label)
        except (ValueError, TypeError):
            return 0

    df['label'] = df['label'].apply(normalize_label)
    return df
