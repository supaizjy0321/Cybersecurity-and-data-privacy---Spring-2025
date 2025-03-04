# **Penetration Testing Report**

## **1. Introduction**

### **Purpose and Scope of the Report**
This report documents the penetration testing conducted on the **user registration system** of the **Booking System (Phase 1)**. The goal of this test was to identify security vulnerabilities and deviations from best practices, particularly in areas such as **input validation, data encryption, and missing security headers**.

### **Testing Schedule and Environment**
- **Old Testing Date:** 02-18-2025  
- **New Testing Date:** 02-21-2025  

- **Environment:** Localhost (`http://localhost:8000/register`)  
- **Testing Methodology:** A combination of automated scanning using ZAP and manual analysis.  
- **Testing User:** Created a test account (`joker/joker123`) for testing.  

### **Scope of Testing**
- **Tested Component:** User Registration Page (only)  
- **Excluded:** Login, Resource Booking, Administrator Functions (not implemented in Phase 1)  
- **Focus Areas:**  
  - Input Validation (SQL Injection, Path Traversal)  
  - Security Headers & Missing Protections  
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

4. **Missing Security Headers (Medium)**  
   - The application **lacks essential security headers**, leaving it vulnerable to XSS, Clickjacking, and MIME-sniffing.  
   - **Fix:** Configure the web server to set **security headers** for protection.  

5. **Format String Error (Medium)**  
   - A potential **format string vulnerability** was detected in the username field.  
   - **Fix:** Use **safe string formatting** methods.  

---

## **3. Findings and Categorization**

### **🔴 1. SQL Injection in Registration Form (High)**
**Risk Level:** 🔴 **High**  
**Number of Instances:** **7**  
**Description:**  
- The registration form **does not properly validate user input**, allowing **SQL Injection**.
- Attackers can **manipulate database queries** to extract or modify data.

**Evidence:**  
SQL Injection payload tested:  
```sql
username=admin' OR '1'='1' -- &password=test123
```

### Recommendations:
- ✅ Use prepared statements to prevent SQL injection.
- ✅ Sanitize user input to remove SQL special characters.

### **🔴 2. Passwords Stored in Plaintext (High)**
**Risk Level:**  🔴 **High**
**Description:**

The database stores passwords in plaintext, which is a major security risk.
Evidence:
Query to database:

SELECT username, password FROM xyz123_users;
Returned:

| username | password  |
|----------|-----------|
| joker    | joker123  |
| admin    | admin123  |
### Recommendations:
- ✅ Hash passwords using bcrypt or Argon2.
- ✅ Never store raw passwords in the database.

### **🔴 3. Path Traversal Vulnerability (High)**
**Risk Level:** 🔴 **High**
**Number of Instances: 3**
**Description:**

The application does not properly sanitize user input, allowing for Path Traversal attacks.
An attacker can manipulate input to access restricted files or directories outside the intended scope.
Evidence:
Testing with:

username=../../../../etc/passwd
Confirmed improper path validation.

### Recommendations:
- ✅ Restrict input to prevent ../ sequences.
- ✅ Use realpath() function to validate file paths.

### **🟡 4. Missing Security Headers (Medium)**
**Risk Level:** 🟡 **Medium**
**Description:**

The server does not set important security headers, leaving the application vulnerable.
Evidence:
Missing:

Content-Security-Policy (CSP)
X-Frame-Options
X-Content-Type-Options
### Recommendations:
- ✅ Set CSP headers to restrict external scripts.
- ✅ Enable X-Frame-Options to prevent Clickjacking.
- ✅ Set X-Content-Type-Options: nosniff.

### **🟡 5. Format String Error (Medium)**
**Risk Level:** 🟡 **Medium**
**Number of Instances: 1**
**Description:**

A Format String vulnerability was detected in the username field.
Evidence:

Attack Input:
ZAP%n%s%n%s%n%s%n%s
The server closed the connection, indicating a potential vulnerability.
### Recommendations:
- ✅ Use proper string formatting functions.
- ✅ Sanitize user input before processing.

### **🟡 6. Missing Anti-Clickjacking Header (Medium)**
**Risk Level: 🟡 Medium**
**Number of Instances: 1**
**Description:**

The X-Frame-Options header is missing, leaving the site vulnerable to Clickjacking attacks.
### Recommendations:
- ✅ Add X-Frame-Options: DENY or SAMEORIGIN header.

### **🟢 7. Application Error Disclosure (Low)**
**Risk Level: 🟢 Low**
**Number of Instances: 1**
**Description:**

The site discloses internal server error messages, which could reveal sensitive information.
### Recommendations:
- ✅ Implement custom error pages to avoid exposing sensitive information.

### **🟢 8. X-Content-Type-Options Header Missing (Low)**
**Risk Level: 🟢 Low**
**Number of Instances: 3**
**Description:**

The X-Content-Type-Options header is missing, allowing MIME-sniffing attacks.
### Recommendations:
- ✅ Set X-Content-Type-Options: nosniff to protect against MIME-sniffing.

---

## **4. Appendices**
**ZAP report in the Booking system - Phase 1 folder**
**Commands used during testing (manual SQL queries)**
