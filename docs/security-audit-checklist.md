# Security Audit Checklist

A comprehensive checklist for conducting security audits on applications and infrastructure.

## How to Use This Checklist

1. **Preparation**: Gather necessary documentation and access
2. **Execution**: Go through each category systematically
3. **Documentation**: Record findings and evidence
4. **Reporting**: Compile results and recommendations
5. **Follow-up**: Track remediation of identified issues

Use the audit tool: `python audit_tool.py`

---

## 1. Authentication & Authorization

### 1.1 Password Security
- [ ] Minimum password length enforced (12+ characters)
- [ ] Password complexity requirements enabled
- [ ] Passwords hashed using strong algorithms (bcrypt, Argon2, scrypt)
- [ ] Unique salt used for each password
- [ ] Password history prevents reuse of recent passwords
- [ ] Account lockout after failed login attempts
- [ ] Passwords not stored in plain text anywhere

### 1.2 Multi-Factor Authentication
- [ ] MFA available for all users
- [ ] MFA required for privileged accounts
- [ ] Multiple MFA methods supported
- [ ] Backup codes provided for account recovery
- [ ] MFA cannot be easily bypassed

### 1.3 Session Management
- [ ] Session IDs are cryptographically random
- [ ] Session timeout configured appropriately
- [ ] Sessions terminated on logout
- [ ] Session ID regenerated after login
- [ ] Cookies marked as HttpOnly
- [ ] Cookies marked as Secure (HTTPS only)
- [ ] SameSite attribute set on cookies

### 1.4 Access Control
- [ ] Principle of least privilege enforced
- [ ] Role-based access control (RBAC) implemented
- [ ] Authorization checked on all sensitive operations
- [ ] Direct object references protected
- [ ] Access permissions reviewed regularly
- [ ] Administrative functions properly protected

---

## 2. Data Protection

### 2.1 Encryption at Rest
- [ ] Sensitive data encrypted in database
- [ ] Strong encryption algorithms used (AES-256)
- [ ] Encryption keys properly managed
- [ ] Keys rotated regularly
- [ ] Key management system (KMS) used

### 2.2 Encryption in Transit
- [ ] TLS 1.2 or higher enforced
- [ ] HTTPS used for all connections
- [ ] Strong cipher suites configured
- [ ] SSL/TLS certificates valid and not expired
- [ ] Certificate chain properly configured
- [ ] HTTP Strict Transport Security (HSTS) enabled

### 2.3 Data Handling
- [ ] Data minimization principles applied
- [ ] Data retention policies defined and enforced
- [ ] Secure data deletion procedures in place
- [ ] Sensitive data masked/redacted in logs
- [ ] Personal data handling complies with regulations
- [ ] Data classification scheme implemented

### 2.4 Backups
- [ ] Regular backups performed
- [ ] Backups encrypted
- [ ] Backup restoration tested
- [ ] Backups stored securely offsite
- [ ] Backup access restricted

---

## 3. Application Security

### 3.1 Input Validation
- [ ] All user inputs validated on server-side
- [ ] Allowlist validation used where possible
- [ ] Input length limits enforced
- [ ] Type checking implemented
- [ ] Special characters handled properly
- [ ] File upload restrictions in place

### 3.2 Injection Prevention
- [ ] SQL injection: Parameterized queries used
- [ ] Command injection: User input not passed to OS commands
- [ ] LDAP injection: Input properly escaped
- [ ] XML injection: XML parser configured securely
- [ ] ORM/database abstraction used properly

### 3.3 Cross-Site Scripting (XSS)
- [ ] Output encoding applied based on context
- [ ] Content Security Policy (CSP) implemented
- [ ] Input sanitization performed
- [ ] Framework XSS protections enabled
- [ ] Dangerous HTML tags/attributes filtered

### 3.4 Cross-Site Request Forgery (CSRF)
- [ ] CSRF tokens implemented for state-changing operations
- [ ] Tokens properly validated
- [ ] SameSite cookie attribute used
- [ ] Origin/Referer headers validated

### 3.5 Security Headers
- [ ] Strict-Transport-Security header set
- [ ] X-Frame-Options header set
- [ ] X-Content-Type-Options header set
- [ ] Content-Security-Policy header configured
- [ ] X-XSS-Protection header set
- [ ] Referrer-Policy header configured
- [ ] Permissions-Policy header set

### 3.6 Error Handling
- [ ] Error messages don't leak sensitive information
- [ ] Stack traces not exposed to users
- [ ] Generic error messages for authentication failures
- [ ] Detailed errors logged server-side
- [ ] Custom error pages configured

### 3.7 API Security
- [ ] Authentication required for APIs
- [ ] Rate limiting implemented
- [ ] Input validation on all API endpoints
- [ ] API versioning in place
- [ ] CORS configured properly (not using *)
- [ ] API keys/tokens secured

---

## 4. Infrastructure Security

### 4.1 Server Hardening
- [ ] Operating system up to date with security patches
- [ ] Unnecessary services disabled
- [ ] Unnecessary ports closed
- [ ] Firewall configured and enabled
- [ ] Secure configurations applied
- [ ] Default accounts disabled/removed

### 4.2 Network Security
- [ ] Network segmentation implemented
- [ ] DMZ configured for public-facing services
- [ ] Internal networks isolated
- [ ] VPN required for remote access
- [ ] Network traffic monitored
- [ ] Intrusion detection/prevention system deployed

### 4.3 Cloud Security (if applicable)
- [ ] Cloud storage buckets not publicly accessible
- [ ] IAM policies follow least privilege
- [ ] Multi-factor authentication enabled for cloud accounts
- [ ] Cloud resources encrypted
- [ ] Security groups/network ACLs properly configured
- [ ] Cloud audit logging enabled
- [ ] Cloud security posture monitored

### 4.4 Container Security (if applicable)
- [ ] Base images from trusted sources
- [ ] Images scanned for vulnerabilities
- [ ] Images regularly updated
- [ ] Containers run as non-root
- [ ] Resource limits configured
- [ ] Secrets not hardcoded in images
- [ ] Container runtime security enabled

---

## 5. Code Security

### 5.1 Secure Development
- [ ] Security requirements defined
- [ ] Security training provided to developers
- [ ] Secure coding guidelines followed
- [ ] Security code reviews conducted
- [ ] Threat modeling performed

### 5.2 Secrets Management
- [ ] No hardcoded secrets in code
- [ ] Secrets not committed to version control
- [ ] Secrets management system used
- [ ] API keys rotated regularly
- [ ] Environment variables used for configuration

### 5.3 Dependency Management
- [ ] Dependencies regularly updated
- [ ] Vulnerability scanning automated
- [ ] Dependency versions pinned
- [ ] Unused dependencies removed
- [ ] Dependencies from trusted sources

### 5.4 Testing
- [ ] Security testing included in QA process
- [ ] Static Application Security Testing (SAST) performed
- [ ] Dynamic Application Security Testing (DAST) performed
- [ ] Penetration testing conducted
- [ ] Security tests automated in CI/CD

---

## 6. Monitoring & Logging

### 6.1 Security Logging
- [ ] Authentication events logged
- [ ] Authorization failures logged
- [ ] Administrative actions logged
- [ ] Security-relevant events logged
- [ ] Logs include timestamp, user, source IP, action

### 6.2 Log Management
- [ ] Logs centrally collected
- [ ] Logs protected from tampering
- [ ] Log retention policy defined
- [ ] Sensitive data not logged
- [ ] Log access restricted

### 6.3 Monitoring & Alerting
- [ ] Security monitoring implemented
- [ ] Automated alerts for security events
- [ ] Anomaly detection configured
- [ ] Security dashboard available
- [ ] 24/7 monitoring for critical systems

---

## 7. Incident Response

### 7.1 Planning
- [ ] Incident response plan documented
- [ ] Incident response team identified
- [ ] Contact information up to date
- [ ] Escalation procedures defined
- [ ] Communication plan established

### 7.2 Detection & Response
- [ ] Incident detection capabilities in place
- [ ] Incident response procedures tested
- [ ] Forensics capabilities available
- [ ] Containment procedures defined
- [ ] Recovery procedures documented

### 7.3 Post-Incident
- [ ] Post-incident reviews conducted
- [ ] Lessons learned documented
- [ ] Remediation actions tracked
- [ ] Incident metrics collected
- [ ] Breach notification procedures defined

---

## 8. Compliance & Policy

### 8.1 Security Policies
- [ ] Information security policy exists
- [ ] Acceptable use policy defined
- [ ] Data classification policy in place
- [ ] Incident response policy documented
- [ ] Policies reviewed and updated annually

### 8.2 Compliance
- [ ] Regulatory requirements identified
- [ ] Compliance controls implemented
- [ ] Compliance audits conducted
- [ ] Compliance documentation maintained
- [ ] Third-party assessments performed (if required)

### 8.3 Vendor Management
- [ ] Third-party security assessments conducted
- [ ] Vendor contracts include security requirements
- [ ] Vendor access monitored
- [ ] Data sharing agreements in place
- [ ] Vendor compliance verified

---

## 9. Physical Security

- [ ] Server room access controlled
- [ ] Access logs maintained
- [ ] Surveillance cameras installed
- [ ] Environmental controls in place
- [ ] Backup power available
- [ ] Fire suppression systems installed
- [ ] Equipment disposal procedures secure

---

## 10. Business Continuity

- [ ] Business continuity plan documented
- [ ] Disaster recovery plan in place
- [ ] Recovery time objectives (RTO) defined
- [ ] Recovery point objectives (RPO) defined
- [ ] BC/DR plans tested regularly
- [ ] Alternate site available if needed

---

## Severity Ratings

Use the following severity ratings when documenting findings:

| Severity | Description |
|----------|-------------|
| **Critical** | Immediate risk of severe impact; requires immediate action |
| **High** | Significant security risk; remediate within 30 days |
| **Medium** | Moderate security risk; remediate within 90 days |
| **Low** | Minor security concern; remediate within 180 days |
| **Informational** | Best practice recommendation; no immediate risk |

---

## Audit Report Template

### Executive Summary
- Audit scope and objectives
- Overall security posture
- Key findings summary
- High-level recommendations

### Detailed Findings
For each finding:
- **Finding ID**: Unique identifier
- **Title**: Brief description
- **Severity**: Critical/High/Medium/Low
- **Description**: Detailed explanation
- **Impact**: Potential consequences
- **Recommendation**: Remediation steps
- **Evidence**: Supporting documentation

### Compliance Status
- Regulatory requirements
- Compliance gaps
- Recommendations

### Action Plan
- Prioritized list of remediation tasks
- Responsible parties
- Target completion dates
- Resources required

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-12 | Initial release |
