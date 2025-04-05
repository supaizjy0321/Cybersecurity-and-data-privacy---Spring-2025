# **Penetration Testing Report**

## **1. Introduction**

### **Purpose and Scope of the Report**
This report documents the penetration testing conducted on the **user registration system** of the **Booking System (Phase 1)**. The goal of this test was to identify security vulnerabilities and deviations from best practices, particularly in areas such as **input validation, data encryption**.

### **Testing Schedule and Environment**
- **Testing Date:** 02-18-2025
- **New Testing Date:** 02-21-2025

- **Environment:** Localhost (`http://localhost:8000/register`)
- **Testing Methodology:** A combination of automated scanning using ZAP and manual analysis.
- **Testing User:** Created a test account (`joker/joker123`) for testing.

### **Scope of Testing**
- **Tested Component:** User Registration Page (only)
- **Excluded:** Login, Resource Booking, Administrator Functions (not implemented in Phase 1)
- **Focus Areas:**
  - Input Validation (SQL Injection, Path Traversal)
  - Data Encryption & Storage Security

### **Methods and Tools Used for Testing**
- **ZAP** – Automated scanning and active attack testing.
- **Kali Linux** – Environment for penetration testing.
- **Chromium Developer Tools** – Inspecting HTTP requests.
- **PostgreSQL Queries** – Analyzing database security.

---

## **2. Summary**

### **Key Findings and Recommendations**
1. **SQL Injection in Registration Form (Critical)**  
   - The registration form is vulnerable to **SQL Injection**, allowing attackers to manipulate database queries.  
   - **Fix:** Use **prepared statements** and **input sanitization**.

2. **Passwords Stored in Plaintext (Critical)**  
   - The database stores **plaintext passwords**, which is a **major security risk** and **GDPR non-compliant**.  
   - **Fix:** Implement **bcrypt** or **Argon2** hashing for password storage.

3. **Path Traversal Vulnerability (Critical)**  
   - ZAP identified a **Path Traversal vulnerability**, indicating improper file path validation.  
   - **Fix:** Sanitize user input and restrict file access.

### **General Assessment of System Security**
The system has **critical security flaws**, including **SQL Injection, Path Traversal, lack of password encryption, and improper input validation**. Immediate fixes are required to **prevent data breaches, unauthorized access, and compliance violations**.

---

## **3. Findings and Categorization**

### **🔴 1. SQL Injection in Registration Form (High)**
**Risk Level:** 🔴 **High**  
**Description:**  
- The registration form **does not properly validate user input**, allowing **SQL Injection**.
- Attackers can **manipulate database queries** to extract or modify data.

**Evidence:**  
SQL Injection payload tested:  
```sql
username=admin' OR '1'='1' -- &password=test123
```

The output of the query was as follows:

| username | password  |
|----------|-----------|
| joker    | joker123  |
| admin    | admin123  |

The passwords are stored in plaintext, making the system susceptible to unauthorized access.

### Recommendations:
- ✅ Use prepared statements to prevent SQL injection.
- ✅ Sanitize user input to remove SQL special characters.

### **🔴 2. Passwords Stored in Plaintext (High)**
**Risk Level:** 🔴 **High**  
**Description:**  
- The database **stores passwords in plaintext**, which is **a major eccurity risk**.
- If an attacker gains access to the database, they can see all user passwords.

**Evidence:**  
Query to database:  
```sql
SELECT username, password FROM xyz123_users;
```

Returned:

| username | password  |
|----------|-----------|
| joker    | joker123  |
| admin    | admin123  |

The passwords are stored in plaintext, making the system susceptible to unauthorized access.

### Recommendations:
- ✅ Hash passwords using bcrypt or Argon2.
- ✅ Never store raw passwords in the database.

### **🔴 3. Path Traversal Vulnerability (High)**
**Risk Level:** 🔴 **High**  
**Description:**  
- The applicaton **does not properly sanitize user input**, allowing for **Path Traversal** attacks.
- An attacker can manipulate input to access restricted files or directories outside the intended scope of the application.


**Evidence:**  
Attempting a Path Traversal attack using the following payload:

username=../../../../etc/passwd


This allowed unauthorized access to system files.

### Recommendations:
- ✅ Implement input validation using an "accept known good" approach (whitelist) to restrict user input.
- ✅ Reject or sanitize inputs containing dangerous characters like `../` and `/`.
- ✅ Use canonicalization functions (e.g., `realpath()` in C) to remove symbolic links and `..` sequences from paths.
- ✅ Limit the permissions of user inputs to minimize potential damage in case of a successful attack.
Explanation:

### **🟡 4. Content Security Policy Header Not Set (Medium)**  
**Risk Level:** 🟡 **Medium**  
**Description:**  
- The application **does not include a Content Security Policy (CSP)** header.
- CSP is an essential security feature that helps mitigate certain types of attacks like **Cross-Site Scripting (XSS)** and **data injection** by specifying which content sources are trusted.

**Evidence:**  
When inspecting the HTTP response headers, the `Content-Security-Policy` header is **missing** in the response from the `/register` page:
- **URL:** `http://localhost:8000/register`
- **Method:** `GET`
- **Response Headers:**  
    ```
    content-encoding: br
    content-length: 357
    content-type: text/html; charset=UTF-8
    date: Thu, 20 Feb 2025 08:23:48 GMT
    vary: Accept-Encoding
    ```

### **Recommendations:**
- ✅ Set the `Content-Security-Policy` header in all HTTP responses.
- ✅ Use a strong CSP policy to restrict the sources for scripts, images, and other resources to trusted domains only.


## **4. Appendices**

### **ZAP report in the Booking system - Phase 1 folder**

### **Commands used during testing (manual SQL queries)**