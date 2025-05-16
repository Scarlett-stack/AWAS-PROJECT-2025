# AWAS-PROJECT-2025: Vulnerable Web Application

**WARNING: This application is deliberately vulnerable for educational purposes. DO NOT deploy in a production environment.**

## Introduction
This web application is designed to demonstrate common web security vulnerabilities and provide hands-on experience in identifying and exploiting them. The application contains three main vulnerabilities that allow attackers to gain unauthorized access and reveal confidential information.

### Web Application Security Context
- Modern web applications play a crucial role in society, handling sensitive data and critical operations
- This project demonstrates new security threats specific to web applications
- Understanding these vulnerabilities is essential for modern cybersecurity

### Technologies Used
- Frontend: HTML, CSS, JavaScript
- Backend: Python Flask Framework
- Database: SQLite
- Authentication: JWT (JSON Web Tokens)

## Security Testing Methodology

### 1. Reconnaissance & Mapping
- Identify application entry points
- Understand the application structure
- Map available endpoints and functionality

### 2. Vulnerability Assessment
- Test client-side controls
- Analyze authentication mechanisms
- Evaluate session management
- Check access controls
- Test for injection vulnerabilities
- Assess cross-user interactions

### 3. Tools Required
- Burp Suite (for intercepting and modifying requests)
- Browser Developer Tools
- JWT testing tools
- SQL injection testing tools

## Objective
Attackers must find and exploit the vulnerabilities to capture specific flags. There are seven flags to be discovered:
1. SQL Injection flag (Database Exploitation)
2. Stored XSS flag (Client-Side Attack)
3. JWT Algorithm None flag (Authentication Bypass)
4. CSRF flag (Profile Update Attack)
5. Path Traversal flag (File System Attack)
6. Broken Access Control flag (Authorization Bypass)
7. Server-Side Template Injection flag (Template Engine Attack)

## Forbidden Exploitation Methods
- Brute force attacks against the login system
- Denial of Service (DoS) attacks
- Server-side file modification
- Attacks against the underlying operating system
- Automated scanning tools without manual verification
- Any attacks outside the scope of OWASP Top 10

## Laboratory 1: SQL Injection in Notes
### Vulnerability Classification
- **Category**: Injection (OWASP Top 10 A03:2021)
- **CWE**: CWE-89 SQL Injection
- **Defense Mechanism Violated**: Input Validation and Sanitization

### Description
The notes creation functionality contains a SQL injection vulnerability due to direct string interpolation in SQL queries. This represents a common injection flaw where user input is not properly sanitized before being used in SQL queries.

### Attack Vectors
1. Basic SQL Injection
   - Using quotes to break out of strings
   - Using SQL comments to bypass restrictions
2. Union-based Injection
   - Extracting data from other tables
3. Boolean-based Injection
   - Inferring data through true/false conditions

### Defense Bypass
- No input validation
- No prepared statements
- Direct string concatenation in queries

### Required Skills
- Understanding of SQL query structure
- Knowledge of SQL injection techniques
- Ability to use Burp Suite or similar proxy tools
- Basic database enumeration skills

## Laboratory 2: Stored XSS Attack
### Vulnerability Classification
- **Category**: Cross-Site Scripting (OWASP Top 10 A03:2021)
- **CWE**: CWE-79 Cross-site Scripting
- **Defense Mechanism Violated**: Output Encoding, Content Security Policy

### Description
The notes display feature doesn't sanitize user input, allowing attackers to inject malicious JavaScript code that will be executed when other users view the notes. This represents a persistent XSS vulnerability where malicious scripts are stored in the database and executed on every page load.

### Attack Vectors
1. Basic Script Injection
   - Injecting `<script>` tags
   - Event handler injection
2. Advanced Techniques
   - DOM manipulation
   - Cookie theft
   - Session hijacking
3. Payload Variations
   - HTML attribute breaking
   - JavaScript URL schemes
   - Encoded payloads

### Defense Bypass
- Lack of input sanitization
- No output encoding
- Missing Content Security Policy
- Insufficient HTML escaping

### Required Skills
- JavaScript fundamentals
- Understanding of HTML and DOM
- Browser Developer Tools
- Web security testing methodology
- Knowledge of XSS payload construction

## Laboratory 3: JWT Algorithm None
### Vulnerability Classification
- **Category**: Broken Authentication (OWASP Top 10 A07:2021)
- **CWE**: CWE-347 Improper Verification of Cryptographic Signature
- **Defense Mechanism Violated**: Cryptographic Controls, Authentication Mechanisms

### Description
The application's JWT implementation is vulnerable to the "algorithm none" attack, allowing attackers to forge valid authentication tokens. This vulnerability stems from improper implementation of JWT verification where the application accepts tokens with the "none" algorithm.

### Attack Vectors
1. Algorithm Manipulation
   - Modifying the JWT header to use 'none' algorithm
   - Removing signature verification
2. Token Forgery
   - Creating custom tokens with elevated privileges
   - Modifying payload claims
3. Authentication Bypass
   - Escalating user privileges
   - Accessing administrative functions

### Defense Bypass
- No algorithm enforcement
- Weak JWT verification
- Missing signature validation
- Improper key management

### Required Skills
- Understanding of JWT structure and claims
- Knowledge of cryptographic concepts
- API testing tools (e.g., Postman, Burp Suite)
- JWT debugging and manipulation tools

## Penetration Testing Methodology

### 1. Information Gathering
- Identify authentication endpoints
- Analyze token structure
- Map application functionality

### 2. Vulnerability Analysis
- Test input validation
- Check authentication mechanisms
- Analyze session management
- Verify access controls

### 3. Exploitation
- Execute SQL injection attacks
- Deploy XSS payloads
- Perform JWT manipulation

### 4. Reporting
- Document findings
- Classify vulnerabilities
- Provide remediation steps

## Laboratory 4: CSRF Attack
### Vulnerability Classification
- **Category**: Cross-Site Request Forgery (OWASP Top 10 A05:2021)
- **CWE**: CWE-352 Cross-Site Request Forgery
- **Defense Mechanism Violated**: Same-Origin Policy, CSRF Tokens

### Description
The profile update functionality lacks CSRF protection, allowing attackers to perform actions on behalf of authenticated users by tricking them into visiting malicious websites.

### Attack Vectors
1. Form Submission
   - Hidden form auto-submission
   - Social engineering tricks
2. State-Changing Operations
   - Profile updates
   - Password changes

### Defense Bypass
- No CSRF tokens
- Missing SameSite cookie attributes
- Predictable form structure

## Laboratory 5: Path Traversal
### Vulnerability Classification
- **Category**: Security Misconfiguration (OWASP Top 10 A05:2021)
- **CWE**: CWE-22 Path Traversal
- **Defense Mechanism Violated**: File System Access Controls

### Description
The file download functionality doesn't properly sanitize file paths, allowing attackers to access files outside the intended directory.

### Attack Vectors
1. Directory Navigation
   - Using '../' sequences
   - Encoded traversal characters
2. File Access
   - System file reading
   - Configuration file access

### Defense Bypass
- Insufficient path sanitization
- Weak file access controls
- Missing path normalization

## Laboratory 6: Broken Access Control
### Vulnerability Classification
- **Category**: Broken Access Control (OWASP Top 10 A01:2021)
- **CWE**: CWE-285 Improper Authorization
- **Defense Mechanism Violated**: Authorization Controls

### Description
The private notes feature lacks proper authorization checks, allowing users to access notes belonging to other users by manipulating request parameters.

### Attack Vectors
1. Parameter Manipulation
   - Modifying note IDs
   - Changing user references
2. Access Control Bypass
   - Direct object references
   - Privilege escalation

### Defense Bypass
- Missing authorization checks
- Insecure direct object references
- Insufficient role validation

## Laboratory 7: Server-Side Template Injection
### Vulnerability Classification
- **Category**: Code Injection (OWASP Top 10 A03:2021)
- **CWE**: CWE-94 Code Injection
- **Defense Mechanism Violated**: Template Engine Security

### Description
The custom profile page template feature allows users to inject template syntax that gets executed server-side, potentially leading to remote code execution.

### Attack Vectors
1. Template Syntax Injection
   - Variable access
   - Object method calls
2. Code Execution
   - Built-in function calls
   - Module imports

### Defense Bypass
- Unsafe template rendering
- Missing input sanitization
- Unrestricted object access

## Enhanced Features

### Modern UI Components
- Responsive Bootstrap 5 design
- Dark/Light theme toggle
- Interactive dashboards
- Real-time notifications

### User Experience
- Markdown support for posts
- User profiles with avatars
- Rich text editor
- File attachments
- Social sharing features

### Security Features
- Password strength meter
- Two-factor authentication (intentionally buggy)
- Activity logging (vulnerable to tampering)
- IP-based rate limiting (bypassable)

## Security Standards and Best Practices
- OWASP Top 10 2021
- OWASP Testing Guide
- OWASP Authentication Guidelines
- CWE/SANS Top 25

## Setup Instructions
1. Ensure Python 3.x is installed
2. Install dependencies: `pip install -r requirements.txt`
3. Start the application: `python3 main.py`
4. Access the application at: http://localhost:5000

## Default Credentials
- Username: admin
- Password: admin123

## Reset Database
To reset the database to its initial state, use the reset endpoint: `/reset`

## Note
This application is part of the Applied Web Application Security (AWAS) course project. It is designed for educational purposes to demonstrate web security concepts and vulnerabilities.
