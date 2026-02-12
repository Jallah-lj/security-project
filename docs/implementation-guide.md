# Security Implementation Guide

This guide provides practical steps for implementing the security best practices covered in this project.

## Table of Contents
1. [Getting Started](#getting-started)
2. [Authentication Implementation](#authentication-implementation)
3. [Data Encryption](#data-encryption)
4. [API Security](#api-security)
5. [Logging and Monitoring](#logging-and-monitoring)
6. [CI/CD Security](#cicd-security)

---

## Getting Started

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Git
- Access to your application repository

### Installation

```bash
# Clone this repository
git clone https://github.com/Jallah-lj/security-project.git
cd security-project

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Authentication Implementation

### Step 1: Password Hashing

```python
# Install bcrypt
pip install bcrypt

# Implement password hashing
import bcrypt

def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password: str, hashed: bytes) -> bool:
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Usage
hashed_pw = hash_password("user_password_123")
is_valid = verify_password("user_password_123", hashed_pw)
```

### Step 2: Session Management

```python
# Flask example
from flask import Flask, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configure secure session
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800  # 30 minutes
)

@app.route('/login', methods=['POST'])
def login():
    # After successful authentication
    session['user_id'] = user.id
    session.permanent = True
    return "Logged in"

@app.route('/logout')
def logout():
    session.clear()
    return "Logged out"
```

---

## Data Encryption

### Encrypting Sensitive Data

```python
from cryptography.fernet import Fernet
import base64
import os

class DataEncryption:
    def __init__(self):
        # In production, load from secure key management system
        self.key = os.environ.get('ENCRYPTION_KEY')
        if not self.key:
            raise ValueError("ENCRYPTION_KEY environment variable not set")
        self.cipher = Fernet(self.key.encode())
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        encrypted = self.cipher.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        decoded = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted = self.cipher.decrypt(decoded)
        return decrypted.decode()

# Usage
encryptor = DataEncryption()
encrypted_ssn = encryptor.encrypt("123-45-6789")
decrypted_ssn = encryptor.decrypt(encrypted_ssn)
```

---

## API Security

### Rate Limiting

```python
# Install Flask-Limiter
pip install Flask-Limiter

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route("/api/data")
@limiter.limit("10 per minute")
def api_data():
    return {"data": "sensitive information"}
```

### API Key Authentication

```python
from functools import wraps
from flask import request, jsonify
import hashlib
import hmac

API_KEYS = {
    "hashed_key_1": {"user": "client1", "permissions": ["read"]},
    "hashed_key_2": {"user": "client2", "permissions": ["read", "write"]}
}

def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({"error": "API key required"}), 401
        
        hashed_key = hash_api_key(api_key)
        
        if hashed_key not in API_KEYS:
            return jsonify({"error": "Invalid API key"}), 401
        
        # Add user info to request context
        request.api_user = API_KEYS[hashed_key]
        return f(*args, **kwargs)
    
    return decorated_function

@app.route("/api/protected")
@require_api_key
def protected_endpoint():
    return jsonify({"user": request.api_user["user"]})
```

---

## Logging and Monitoring

### Security Logging

```python
import logging
import json
from datetime import datetime

class SecurityLogger:
    def __init__(self, log_file='security.log'):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def log_event(self, event_type, user, ip_address, details):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user': user,
            'ip_address': ip_address,
            'details': details
        }
        self.logger.info(json.dumps(log_entry))

# Usage
security_log = SecurityLogger()

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if authenticate(username, password):
        security_log.log_event(
            event_type='login_success',
            user=username,
            ip_address=request.remote_addr,
            details={'method': 'password'}
        )
        return "Success"
    else:
        security_log.log_event(
            event_type='login_failure',
            user=username,
            ip_address=request.remote_addr,
            details={'reason': 'invalid_credentials'}
        )
        return "Failed", 401
```

---

## CI/CD Security

### GitHub Actions Security Workflow

```yaml
# .github/workflows/security.yml
name: Security Checks

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install bandit safety pip-audit
    
    - name: Run Bandit (SAST)
      run: bandit -r . -f json -o bandit-report.json
      continue-on-error: true
    
    - name: Run Safety (dependency check)
      run: safety check --json
      continue-on-error: true
    
    - name: Run pip-audit
      run: pip-audit
      continue-on-error: true
    
    - name: Run security scanner
      run: python security_scanner.py
    
    - name: Upload security reports
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: |
          bandit-report.json
```

### Pre-commit Hooks

```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml << EOF
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: '1.7.5'
    hooks:
      - id: bandit
        args: ['-c', 'pyproject.toml']
  
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
      - id: check-merge-conflict
      - id: check-yaml
      - id: end-of-file-fixer
      - id: trailing-whitespace
EOF

# Install hooks
pre-commit install
``` 

---

## Security Checklist for Deployment

Before deploying to production:

- [ ] All secrets moved to environment variables or secret management system
- [ ] HTTPS enabled with valid certificates
- [ ] Security headers configured
- [ ] Rate limiting implemented
- [ ] Logging and monitoring set up
- [ ] Dependency vulnerabilities resolved
- [ ] Security testing completed
- [ ] Backup and recovery procedures tested
- [ ] Incident response plan documented
- [ ] Security audit conducted

---

## Additional Resources

- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)
- [Flask Security Considerations](https://flask.palletsprojects.com/en/2.3.x/security/)
- [Django Security](https://docs.djangoproject.com/en/stable/topics/security/)

---

## Support

For issues or questions:
1. Check existing documentation
2. Review security best practices guide
3. Open an issue on GitHub
4. Contact security team

---

Last Updated: 2026-02-12
``},{