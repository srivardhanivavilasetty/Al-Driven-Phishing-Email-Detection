# AI-Driven Phishing Email Detection Using NLP

A complete MCA-level web application that detects phishing emails using NLP, machine learning, and email metadata analysis.

## Project Description

This project is a Flask-based web app with user authentication, email analysis, model comparison, admin controls, and a user-friendly dashboard. It combines TF-IDF text analysis with metadata and structural features to classify emails as phishing or legitimate.

## Objectives

- Detect phishing emails using NLP and machine learning
- Provide risk scores and explainable warning indicators
- Support user registration, login, and prediction history
- Provide an admin dashboard and model performance visualization

## Features

- Email preprocessing and NLP feature extraction
- Metadata and structural feature generation
- TF-IDF + custom features
- Logistic Regression, Naive Bayes, Random Forest, MLPClassifier
- Best model selection and dashboard charts
- User and admin portals
- MySQL-backed history and model tracking

## Technology Stack

- Python, Flask
- MySQL, mysql-connector-python
- pandas, numpy, scikit-learn, scipy
- NLTK, joblib, matplotlib
- HTML5, CSS3, JavaScript, Bootstrap 5

## Project Structure

- `app.py` - Flask application entrypoint
- `config.py` - Configuration and environment variable loading
- `database/database.sql` - SQL schema for MySQL setup
- `ml/` - Machine learning preprocessing, training, prediction
- `templates/` - HTML templates
- `static/` - CSS, JavaScript, images
- `dataset/` - Sample dataset files
- `models/` - Saved model and vectorizer files

## Dataset Format

The dataset CSV must contain columns:

- `sender`
- `subject`
- `body`
- `label`

Accepted labels:

- `phishing` / `legitimate`
- `1` / `0`

## Installation

Open PowerShell in the project folder and run:

```powershell
python -m venv env
.\
e\Scripts\Activate.ps1
pip install -r requirements.txt
```

## MySQL Setup

Create the database and tables:

```powershell
mysql -u root -p < database\database.sql
```

## Environment Configuration

Create a `.env` file in the project root with:

```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=yourpassword
DB_NAME=phishing_detection
SECRET_KEY=your-secret-key
```

## Training the Model

```powershell
python ml\train_models.py
```

## Running the Application

```powershell
python app.py
```

## Default Admin Creation

Use the registration form and manually set the `role` field to `admin` in the database for the first administrator if needed.

## Troubleshooting

- If model files are missing, run `python ml\train_models.py`.
- Ensure MySQL is running and `.env` values match the database credentials.
- If templates are not found, make sure you execute from the project root.
