import os
import re
import joblib
from scipy.sparse import csr_matrix
from ml.preprocessing import clean_text
from ml.feature_extraction import extract_metadata_features, build_feature_matrix, get_metadata_feature_names
from config import Config

SUSPICIOUS_INDICATORS = [
    ('suspicious_url', 'Suspicious URL detected'),
    ('ip_url_presence', 'IP-address-based URL detected'),
    ('urgency_keyword_count', 'Urgent language detected'),
    ('suspicious_keyword_count', 'Suspicious keyword language detected'),
    ('exclamation_count', 'Multiple exclamation marks detected'),
    ('html_tag_presence', 'HTML content detected')
]


def load_artifacts():
    model_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'best_model.pkl')
    vectorizer_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'tfidf_vectorizer.pkl')
    if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
        raise FileNotFoundError('Model or vectorizer artifact missing. Run ml/train_models.py first.')
    model = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)
    return model, vectorizer


def predict_email(sender: str, subject: str, email_body: str) -> dict:
    model, vectorizer = load_artifacts()
    features = extract_metadata_features(sender, subject, email_body)
    clean_body_text = clean_text(subject, email_body)
    text_matrix = vectorizer.transform([clean_body_text])
    full_features = build_feature_matrix(text_matrix, [features])

    prediction_value = model.predict(full_features)[0]
    prediction_label = 'PHISHING' if prediction_value == 1 else 'LEGITIMATE'
    confidence = 0.0
    if hasattr(model, 'predict_proba'):
        confidence = float(model.predict_proba(full_features)[0][prediction_value])
    elif hasattr(model, 'decision_function'):
        decision = float(model.decision_function(full_features)[0])
        confidence = 1 / (1 + pow(2.71828, -decision))

    risk_base = confidence * 100
    risk_adjustment = sum([
        10 if features['suspicious_url_count'] > 0 else 0,
        15 if features['ip_url_presence'] else 0,
        10 if features['suspicious_keyword_count'] > 1 else 0,
        10 if features['urgency_keyword_count'] > 0 else 0,
        5 if features['exclamation_count'] > 1 else 0,
        5 if features['html_tag_presence'] else 0,
    ])
    risk_score = min(100, int(risk_base + risk_adjustment))
    if risk_score < 30:
        risk_level = 'LOW'
    elif risk_score < 70:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'HIGH'

    warning_indicators = []
    if features['suspicious_url_count'] > 0:
        warning_indicators.append('Suspicious URL detected')
    if features['ip_url_presence']:
        warning_indicators.append('IP-address-based URL detected')
    if features['urgency_keyword_count'] > 0:
        warning_indicators.append('Urgent language detected')
    if features['suspicious_keyword_count'] > 0:
        warning_indicators.append('Suspicious keyword language detected')
    if features['exclamation_count'] > 1:
        warning_indicators.append('Multiple exclamation marks detected')
    if features['html_tag_presence']:
        warning_indicators.append('HTML content detected')
    if sender and ('noreply' in sender.lower() or 'admin' in sender.lower()) and prediction_label == 'PHISHING':
        warning_indicators.append('Suspicious sender pattern detected')

    return {
        'prediction': prediction_label,
        'confidence': round(confidence * 100, 2),
        'risk_score': risk_score,
        'risk_level': risk_level,
        'warning_indicators': warning_indicators,
        'extracted_features': features
    }
