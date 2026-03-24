# Flask AppSec Lab

This project is a simple Flask-based web application built to demonstrate common OWASP Top 10 vulnerabilities and how to fix them.

## Overview
The application includes:
- Login functionality
- Search functionality
- Admin panel

This lab was created to understand how real-world application vulnerabilities occur and how to remediate them.

---

## Vulnerabilities Demonstrated

### 1. SQL Injection
- **Issue:** User input was directly included in SQL queries
- **Impact:** Allowed authentication bypass using payloads like `' OR '1'='1`
- **Fix:** Implemented parameterized queries to separate code from data

---

### 2. Cross-Site Scripting (XSS)
- **Issue:** User input was rendered directly in the browser
- **Impact:** Allowed execution of malicious JavaScript
- **Fix:** Escaped user input using `markupsafe.escape()`

---

### 3. Broken Access Control
- **Issue:** Admin page was accessible without authentication
- **Impact:** Unauthorized users could access sensitive data
- **Fix:** Added session-based authorization checks

---

## Tech Stack
- Python
- Flask
- SQLite

---

## How to Run

```bash
pip install flask
python app.py




## Demo Flow (How I Tested)

1. Tried normal login → worked  
2. Tested SQL Injection using `' OR '1'='1` → bypassed login (before fix)  
3. Fixed using parameterized queries → attack failed  
4. Tested XSS using `<script>alert('hacked')</script>` → script executed (before fix)  
5. Fixed using escaping → script displayed as text  
6. Tested admin access without login → accessible (before fix)  
7. Added session check → restricted access  

---

## Author
Sai (M.S. Cybersecurity, USF)
```bash
pip install flask
python app.py
