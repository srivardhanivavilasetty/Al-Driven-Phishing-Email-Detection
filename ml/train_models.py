import json
import os
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from ml.preprocessing import prepare_dataframe
from ml.feature_extraction import extract_metadata_features, build_feature_matrix, get_metadata_feature_names
from config import Config


import csv


def load_dataset(path):
    records = []
    with open(path, 'r', encoding='utf-8', newline='') as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader, None)
        if header is None or header != ['sender', 'subject', 'body', 'label']:
            raise ValueError("Dataset must contain header columns: sender, subject, body, label")
        for row_number, row in enumerate(reader, start=2):
            if len(row) < 4:
                raise ValueError(f"Invalid dataset row at line {row_number}: expected at least 4 fields, got {len(row)}")
            sender = row[0].strip()
            subject = row[1].strip()
            label = row[-1].strip()
            body = ','.join(field.strip() for field in row[2:-1])
            records.append({
                'sender': sender,
                'subject': subject,
                'body': body,
                'label': label
            })
    df = pd.DataFrame(records)
    required_columns = {'sender', 'subject', 'body', 'label'}
    if not required_columns.issubset(df.columns):
        raise ValueError(f"Dataset must contain columns: {required_columns}")
    return df


def evaluate_model(name, model, X_test, y_test):
    y_pred = model.predict(X_test)
    y_proba = None
    if hasattr(model, 'predict_proba'):
        y_proba = model.predict_proba(X_test)[:, 1]
    elif hasattr(model, 'decision_function'):
        y_proba = model.decision_function(X_test)

    metrics = {
        'model_name': name,
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred, zero_division=0),
        'recall': recall_score(y_test, y_pred, zero_division=0),
        'f1_score': f1_score(y_test, y_pred, zero_division=0),
        'classification_report': classification_report(y_test, y_pred, zero_division=0, output_dict=True),
        'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
        'probabilities': y_proba.tolist() if y_proba is not None else None,
    }
    return metrics


def plot_confusion_matrix(conf_matrix, model_name, folder):
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.matshow(conf_matrix, cmap='Blues')
    for i in range(conf_matrix.shape[0]):
        for j in range(conf_matrix.shape[1]):
            ax.text(j, i, str(conf_matrix[i, j]), ha='center', va='center', color='black')
    ax.set_xlabel('Predicted')
    ax.set_ylabel('Actual')
    ax.set_title(f'{model_name} Confusion Matrix')
    plt.xticks([0, 1], ['Legitimate', 'Phishing'])
    plt.yticks([0, 1], ['Legitimate', 'Phishing'])
    plt.tight_layout()
    output_path = os.path.join(folder, f'{model_name.lower().replace(" ", "_")}_confusion.png')
    fig.savefig(output_path)
    plt.close(fig)
    return output_path


def plot_model_comparison(results, folder):
    names = [result['model_name'] for result in results]
    f1_scores = [result['f1_score'] for result in results]
    recalls = [result['recall'] for result in results]
    accuracies = [result['accuracy'] for result in results]

    fig, ax = plt.subplots(figsize=(8, 5))
    x = range(len(names))
    ax.plot(x, f1_scores, marker='o', label='F1 Score')
    ax.plot(x, recalls, marker='s', label='Recall')
    ax.plot(x, accuracies, marker='^', label='Accuracy')
    ax.set_xticks(x)
    ax.set_xticklabels(names)
    ax.set_xlabel('Model')
    ax.set_ylabel('Score')
    ax.set_title('Model Comparison')
    ax.legend()
    plt.tight_layout()
    output_path = os.path.join(folder, 'model_comparison_chart.png')
    fig.savefig(output_path)
    plt.close(fig)
    return output_path


def main():
    dataset_path = os.path.join(os.path.dirname(__file__), '..', 'dataset', 'raw_emails.csv')
    output_folder = os.path.join(os.path.dirname(__file__), '..', 'static', 'images')
    os.makedirs(output_folder, exist_ok=True)
    model_folder = os.path.join(os.path.dirname(__file__), '..', 'models')
    os.makedirs(model_folder, exist_ok=True)

    df = load_dataset(dataset_path)
    df = prepare_dataframe(df)
    df['metadata'] = df.apply(lambda row: extract_metadata_features(row['sender'], row['subject'], row['body']), axis=1)

    vectorizer = TfidfVectorizer(max_features=2500, ngram_range=(1, 2))
    X_text = vectorizer.fit_transform(df['clean_text'])
    X = build_feature_matrix(X_text, df['metadata'].tolist())
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    models = [
        ('Logistic Regression', LogisticRegression(max_iter=500, random_state=42)),
        ('Multinomial Naive Bayes', MultinomialNB()),
        ('Random Forest', RandomForestClassifier(n_estimators=100, random_state=42)),
        ('MLP Classifier', MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=500, random_state=42))
    ]

    results = []
    best_model = None
    best_f1 = -1
    for name, clf in models:
        clf.fit(X_train, y_train)
        metrics = evaluate_model(name, clf, X_test, y_test)
        results.append(metrics)
        plot_confusion_matrix(confusion_matrix(y_test, clf.predict(X_test)), name, output_folder)

        if metrics['f1_score'] > best_f1:
            best_f1 = metrics['f1_score']
            best_model = clf

    comparison_plot = plot_model_comparison(results, output_folder)
    model_results = {
        'model_results': results,
        'best_model': max(results, key=lambda item: item['f1_score']),
        'comparison_chart': os.path.basename(comparison_plot),
    }

    joblib.dump(best_model, os.path.join(model_folder, 'best_model.pkl'))
    joblib.dump(vectorizer, os.path.join(model_folder, 'tfidf_vectorizer.pkl'))
    with open(os.path.join(model_folder, 'model_results.json'), 'w', encoding='utf-8') as f:
        json.dump(model_results, f, indent=4)

    feature_config = {
        'metadata_features': get_metadata_feature_names(),
        'text_feature_method': 'tfidf',
        'vectorizer': 'tfidf_vectorizer.pkl'
    }
    with open(os.path.join(model_folder, 'feature_config.json'), 'w', encoding='utf-8') as f:
        json.dump(feature_config, f, indent=4)

    print('Training complete. Best model saved to models/best_model.pkl')
    print('Vectorizer saved to models/tfidf_vectorizer.pkl')
    print('Model results saved to models/model_results.json')


if __name__ == '__main__':
    main()
