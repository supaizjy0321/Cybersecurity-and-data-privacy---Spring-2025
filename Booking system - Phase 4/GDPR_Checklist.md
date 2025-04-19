# GDPR Compliance Checklist – Web-based Booking System

| **Result** | **Personal data mapping and minimization** |
| :----: | :--- |
| &nbsp;⚠️&nbsp;(Personal data (name, email, age) is clearly present in registration, but there’s no explicit documentation or centralized data mapping.) | Have all personal data collected and processed in the system been<br> identified? (e.g., name, email, age, username) |
| &nbsp;✅&nbsp;(The system only collect necessary personal data.) | Have you ensured that only necessary personal data is collected (data minimization)? |
| &nbsp;✅&nbsp;(Person who is under 15 years old cannot register in the Booking System.) | Is user age recorded to verify that the booker is over 15 years old? |

---

| **Result** | **User registration and management** |
| :----: | :--- |
| &nbsp;⚠️&nbsp;(It has a checkbox "I accept Terms of Service". However, it's blank after clicking the terms.) | Does the registration form (page) include GDPR-compliant consent for processing<br> personal data (e.g., acceptance of the privacy policy)?|
| &nbsp;❌&nbsp;(No clear edit/delete functions for users’ own accounts.) | Can users view, edit, and delete their own personal data via their account? |
| &nbsp;⚠️&nbsp;(The foundation exists (admin can delete something), but the full right-to-be-forgotten functionality isn't implemented yet.) | Is there a mechanism for the administrator to delete a reserver in<br> accordance with the "right to be forgotten"? |
| &nbsp;✅&nbsp;(Person under 15 cannot register and book.)| Is underage registration (under 15 years) and booking functionality restricted? |

---

| **Result** | **Booking visibility** |
| :----: | :--- |
| &nbsp;✅&nbsp;(Yes, only resource name and reservation period.) | Are bookings visible to non-logged-in users only at the resource level<br> (without any personal data)? |
| &nbsp;❌&nbsp;(Regular users should not be able to access personal data of other users (e.g., emails). This is a GDPR breach and needs to be fixed with proper access control and anonymization of booking visibility.) | Is it ensured that names, emails, or other personal data of bookers are not exposed<br> publicly or to unauthorized users? |

--- 

| **Result** | **Access control and authorization** |
| :----: | :--- |
| &nbsp;✅/❌/⚠️&nbsp; | Have you ensured that only administrators can add, modify, and delete<br> resources and bookings? |
| &nbsp;✅/❌/⚠️&nbsp; | Is the system using role-based access control (e.g., reserver vs. administrator)? |
| &nbsp;✅/❌/⚠️&nbsp; | Are administrator privileges limited to ensure GDPR compliance (e.g., administrators<br> cannot use data for unauthorized purposes)? |

---

| **Result** | **Privacy by Design Principles** |
| :----: | :--- |
| &nbsp;❌&nbsp;(Administrators cannot delete (a required permission is missing). Reservers (non-admin users) can modify other users’ bookings and resources. This is a major GDPR violation — it allows unauthorized access to personal data and changes to system resources.) | Has Privacy by Default been implemented (e.g., collecting the minimum data by default)? |
| &nbsp;✅&nbsp;(No critical errors.) | Are logs implemented without unnecessarily storing personal data? |
| &nbsp;⚠️&nbsp;(The registration and login forms only ask for username and password — this supports data minimization.However, passwords are transmitted via HTTP (no HTTPS enforced), which is not secure. No CAPTCHA or rate-limiting to protect login forms from brute force. No CSRF tokens or input validation on form fields were clearly observed.) | Are forms and system components designed with data protection in mind<br> (e.g., secured login, minimal fields)? |

---

| **Result** | **Data security** |
| :----: | :--- |
| &nbsp;❌&nbsp;(No CSRF token in forms. No mention of helmet.js or other protections. Uses MongoDB, but no escaping/sanitizing seen.) | Are CSRF, XSS, and SQL injection protections implemented? |
| &nbsp;✅&nbsp;(bcryptjs is used in register route – secure.) | Are passwords securely hashed using a strong algorithm (e.g., bcrypt, Argon2)? |
| &nbsp;⚠️&nbsp;(No mention in code; assume missing unless stated.) | Are data backup and recovery processes GDPR-compliant? |
| &nbsp;⚠️&nbsp;(Depends on deployment — not stated in Docker or README. Needs clarification.) | Is personal data stored in data centers located within the EU? |

---

| **Result** | **Data anonymization and pseudonymization** |
| :----: | :--- |
| &nbsp;❌&nbsp;(Data is stored with personal info — no anonymization or retention policies evident.) | Is personal data anonymized where possible? |
| &nbsp;❌&nbsp;(No pseudonymization techniques visible.) | Are pseudonymization techniques used to protect data while maintaining its utility? |

---

| **Result** | **Data subject rights** |
| :----: | :--- |
| &nbsp;❌&nbsp;(No route or UI for downloading personal data.) | Can users download or request all personal data related to them (data access request)? |
| &nbsp;❌&nbsp;(Users cannot delete their accounts — no feature implemented.) | Is there an interface or process for users to request the deletion of their personal data? |
| &nbsp;❌&nbsp;(No consent feature, so withdrawal is also missing.)| Can users withdraw their consent for data processing? |

---

| **Result** | **Documentation and communication** |
| :----: | :--- |
| &nbsp;⚠️&nbsp;(Yes, there's a link, but it's blank.) | Is there a privacy policy available to users during registration and easily accessible? |
| &nbsp;⚠️&nbsp;(Unclear, possibly in external docs.) | Are administrators and developers provided with documented data protection practices <br>and processing activities? |
| &nbsp;❌&nbsp;(No file or documentation describing how breaches are handled.) | Is there a documented data breach response process (e.g., how to notify authorities <br>and users of a breach)? |

---

**Symbols used:**  
✅ Pass (a note can be added)  
❌ Fail (a note can be added)  
⚠️ Attention (a note can be added)
