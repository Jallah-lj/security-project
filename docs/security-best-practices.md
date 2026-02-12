# Security Best Practices Guide

## Table of Contents
1. [Authentication & Authorization](#authentication--authorization)
2. [Data Protection & Encryption](#data-protection--encryption)
3. [Input Validation & Sanitization](#input-validation--sanitization)
4. [Secure Communication](#secure-communication)
5. [Error Handling & Logging](#error-handling--logging)
6. [Dependency Management](#dependency-management)
7. [Code Review & Testing](#code-review--testing)
8. [Incident Response](#incident-response)

---

## Authentication & Authorization

### 1.1 Password Security
- **Minimum Length**: Require passwords of at least 12 characters
- **Complexity**: Enforce mix of uppercase, lowercase, numbers, and special characters
- **Password Hashing**: Use bcrypt, scrypt, or Argon2 (never MD5 or SHA1)
- **Salting**: Always use unique salts for each password
- **Storage**: Never store passwords in plain text

```python
# Good Practice
import bcrypt

password = b"user_password"
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password, salt)
```

### 1.2 Multi-Factor Authentication (MFA)
- Implement MFA for all privileged accounts
- Support multiple MFA methods (TOTP, SMS, hardware tokens)
- Provide backup codes for account recovery

### 1.3 Session Management
- Use secure, random session IDs
- Implement session timeout (15-30 minutes for sensitive applications)
- Regenerate session ID after login
- Implement logout functionality that destroys sessions
- Use httpOnly and secure flags for cookies

```python
# Django example
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
```

### 1.4 Access Control
- Implement principle of least privilege
- Use role-based access control (RBAC)
- Regularly review and audit permissions
- Implement proper authorization checks on all endpoints

---

## Data Protection & Encryption

### 2.1 Encryption at Rest
- Encrypt sensitive data in databases
- Use AES-256 or equivalent strong encryption
- Protect encryption keys with key management systems (KMS)

```python
# Example using cryptography library
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)
encrypted_data = cipher.encrypt(b"sensitive data")
```

### 2.2 Encryption in Transit
- Use TLS 1.2 or higher (disable TLS 1.0 and 1.1)
- Implement HTTPS for all web applications
- Use strong cipher suites
- Implement certificate pinning for mobile apps

### 2.3 Data Minimization
- Only collect data that is necessary
- Implement data retention policies
- Securely delete data when no longer needed
- Anonymize or pseudonymize data when possible

### 2.4 Compliance
- **GDPR**: Implement right to access, right to be forgotten
- **HIPAA**: Ensure PHI is protected appropriately
- **PCI DSS**: Follow requirements for payment card data
- **CCPA**: Implement data privacy rights for California residents

---

## Input Validation & Sanitization

### 3.1 Server-Side Validation
- **Never trust client-side validation alone**
- Validate all input on the server
- Use allowlists (whitelists) over denylists (blacklists)
- Implement proper type checking

```python
# Example validation
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None
```

### 3.2 SQL Injection Prevention
- **Always use parameterized queries/prepared statements**
- Never concatenate user input into SQL queries
- Use ORM frameworks properly
- Implement least privilege for database accounts

```python
# Good Practice - Parameterized Query
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

# Bad Practice - String Concatenation
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
```

### 3.3 Cross-Site Scripting (XSS) Prevention
- Escape output based on context (HTML, JavaScript, URL)
- Use Content Security Policy (CSP) headers
- Implement input sanitization
- Use frameworks with built-in XSS protection

```python
# Flask example with CSP
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'script-src': "'self'",
    'style-src': "'self'"
})
```

### 3.4 Cross-Site Request Forgery (CSRF) Protection
- Implement CSRF tokens for state-changing operations
- Validate origin and referrer headers
- Use SameSite cookie attribute

---

## Secure Communication

### 4.1 API Security
- Implement rate limiting
- Use API keys or OAuth 2.0 for authentication
- Validate and sanitize all API inputs
- Implement proper error handling (don't leak sensitive info)
- Use API versioning

### 4.2 Security Headers
Implement the following HTTP security headers:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### 4.3 CORS Configuration
- Only allow trusted origins
- Don't use wildcard (*) in production
- Validate origin header

```python
# Flask-CORS example
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["https://trusted-domain.com"])
```

---

## Error Handling & Logging

### 5.1 Error Messages
- Never expose stack traces to users
- Don't leak sensitive information in errors
- Use generic error messages for authentication failures
- Log detailed errors server-side

```python
# Good Practice
try:
    # risky operation
    pass
except Exception as e:
    logger.error(f"Error processing request: {str(e)}")
    return {"error": "An error occurred processing your request"}, 500
```

### 5.2 Security Logging
Log the following security events:
- Authentication attempts (success and failure)
- Authorization failures
- Input validation failures
- Security-relevant configuration changes
- Administrative actions

### 5.3 Log Protection
- Protect log files from unauthorized access
- Don't log sensitive data (passwords, credit cards, PII)
- Implement log retention policies
- Use centralized logging for monitoring

---

## Dependency Management

### 6.1 Vulnerability Scanning
- Regularly scan dependencies for known vulnerabilities
- Use tools like `pip-audit`, `safety`, or `Snyk`
- Automate vulnerability scanning in CI/CD pipeline

```bash
# Install and run pip-audit
pip install pip-audit
pip-audit
```

### 6.2 Dependency Updates
- Keep dependencies up to date
- Monitor security advisories
- Test updates in staging before production
- Pin dependency versions in production

### 6.3 Supply Chain Security
- Verify package integrity (checksums, signatures)
- Use private package repositories when possible
- Review dependencies before adding them
- Minimize number of dependencies

---

## Code Review & Testing

### 7.1 Security Code Review
- Conduct peer reviews for all code changes
- Use security-focused checklists
- Look for common vulnerabilities (OWASP Top 10)
- Review authentication and authorization logic carefully

### 7.2 Static Application Security Testing (SAST)
- Use tools like Bandit (Python), ESLint, SonarQube
- Integrate SAST into CI/CD pipeline
- Fix high-severity findings before deployment

```bash
# Run Bandit for Python
pip install bandit
bandit -r . -f json -o bandit-report.json
```

### 7.3 Dynamic Application Security Testing (DAST)
- Test running applications for vulnerabilities
- Use tools like OWASP ZAP, Burp Suite
- Conduct regular penetration testing

### 7.4 Security Testing
- Write security-focused unit tests
- Test authentication and authorization
- Test input validation
- Test rate limiting and session management

---

## Incident Response

### 8.1 Incident Response Plan
- Document incident response procedures
- Identify incident response team members
- Define communication channels
- Establish escalation procedures

### 8.2 Detection and Monitoring
- Implement security monitoring and alerting
- Use intrusion detection systems (IDS)
- Monitor for anomalous behavior
- Set up automated alerts for security events

### 8.3 Response and Recovery
- Have a plan for containment
- Document incident details
- Preserve evidence for forensics
- Implement recovery procedures
- Conduct post-incident review

### 8.4 Breach Notification
- Understand legal requirements (GDPR, state laws)
- Have notification templates prepared
- Establish timeline for notification
- Coordinate with legal and PR teams

---

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Security Resources](https://www.sans.org/security-resources/)
- [Have I Been Pwned](https://haveibeenpwned.com/)

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-12 | Initial release |
