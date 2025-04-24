# Table of contents
1. [Cisco - Introduction to Cybersecurity](#cisco)
2. [PortSwigger](#portswigger)
    1. [Dashboard of all the labs](#dashboard)
    2. [Topic SQL injection](#sqlinjection)
    3. [Topic Authentication](#authentication)
    4. [Topic Access control](#accesscontrol)
    5. [Topic OS command injection](#oscommandinjection)
    6. [Topic Path traversal](#pathtraversal)
    7. [Topic Cross-site scripting](#crosssitescripting)
  
3. [The Booking system project](#booking)
4. [Logbook](#logbook)

## 1. Cisco - Introduction to Cybersecurity <a name="cisco"></a>
<img src="https://github.com/supaizjy0321/Cybersecurity-and-data-privacy---Spring-2025/blob/main/cisco%20score.png" width="800"/>

##### Reflection: This introductory course takes me inside the world of cybersecurity. I have learned cybersecurity basics to protesct my personal digital life. Also, I have learned the biggest securtiy challenges companies, goverments, and educational institutions face today. Sometimes the exam wss tricky for me, because I mixed some professional terms. But this course worthes learning, it's a good start for cybersecurity world.

## 2. PortSwigger <a name="portswigger"></a>
### Dashboard of all the labs <a name="dashboard"></a>

<img src="https://github.com/supaizjy0321/Cybersecurity-and-data-privacy---Spring-2025/blob/main/dashboard.png" width="300"/>

### Topic SQL injection <a name="sqlinjection"></a>
 - SQL injection vulnerability in WHERE clause allowing retrieval of hidden data -> perform a SQL injection attack using category=Gifts'+OR+1=1-- for all the product in Gift category
 - SQL injection vulnerability allowing login bypass -> use the SQL comment sequence -- to remove the password check from the WHERE clause of the query

### Topic Authentication <a name="authentication"></a>
 - Username enumeration via different responses -> try Burp Intruder to find a valid username
 - Password reset broken logic -> by "forget the password" to reset the password

### Topic Access control <a name="accesscontrol"></a>
 - Unprotected admin functionality -> the core is to replace  /robots.txt with /administrator-panel to load the admin panel
 - User role can be modified in user profile -> the lab reinforces the importance of validating user privileges on the server side
 - Unprotected admin functionality with unpredictable URL -> some JavaScript disclosesthe URL of the admin panel
 - User role controlled by request parameter -> check admin in cookie
 - User ID controlled by request parameter -> just change id parameter to carlos
 - User ID controlled by request parameter, with unpredictable user IDs -> change User ID
 - User ID controlled by request parameter with data leakage in redirect -> sensitive information is leaked in the body of a redirect response

### Topic OS command injection <a name="oscommandinjection"></a>
 - OS command injection, simple case -> use burp to check product stock

### Topic Path traversal <a name="pathtraversal"></a>
 - File path traversal, simple case -> forward the product then find path traversal vulnerability

### Topic Cross-site scripting <a name="crosssitescripting"></a>
 - Reflected XSS into HTML context with nothing encoded -> solve the majority of our XSS labs by invoking alert() in a simulated victim's browser
 - Stored XSS into HTML context with nothing encoded -> still using alert() but stored XSS
 - DOM XSS in document.write sink using source location.search -> also calls alert() to perform an attack
 - DOM XSS in innerHTML sink using source location.search -> use alert() function in the search blog functionality
 - DOM XSS in jQuery anchor href attribute sink using location.search source -> the point is to change href attribute

##### Reflection: Completing many PortSwigger labs has significantly deepened my understanding of web security. I learned how vulnerabilities like XSS, SQL injection, and broken authentication actually work in practice. The hands-on approach helped me think like an attacker, which in turn improved how I approach secure coding. I’ve become more comfortable using tools like Burp Suite and analyzing HTTP traffic. These labs made security feel real, not abstract, and have made me more mindful of potential risks in my own development work. Overall, it’s been a challenging but rewarding learning experience.

 



## 3. The Booking system project <a name="booking"></a>
 - Phase 1: In this section, we need to successfully using booking system on kali.Actually, because my laptop is macOS, the docker cannot work. However, this experience let me learn something about docker. I took most time on installing every tool successfully. I learned an convenient method to find vulnerabilities, using ZAP. It's convenient to find vulnerabilities automatically.
 - Phase 2: Based on teacher's hint, I successfully find all passwords by performing password hacking attack. I used dictionary attacks for some accounts and pattern analysis for others based on hints. Dictionary attacks worked well, while brute force didn’t. Guessing structured passwords took the most time. I learned that small clues can significantly narrow the search and logical thinking is often more effective than automation alone.
 - Phase 3: I tested authorization by exploring browser features, analyzing roles (guest, reserver, admin), and checking access control using ZAP and wfuzz. Role-based restrictions worked well, but manual table updates were time-consuming. Discovering hidden endpoints and verifying backend checks took the most effort. I learned how critical backend enforcement is and how tools like ZAP and wfuzz help uncover insecure direct access paths.
 - I reviewed GDPR basics, updated the app, and added the GDPR checklist to GitHub. I checked the privacy, terms of service, and cookie policy pages—some were empty, so I created markdown pages with appropriate content. Writing the policies took the most time. I learned how important clear, GDPR-compliant policies are for user trust and legal compliance.

##### Reflection: Through this topic, I learned how critical authorization, access control, and data protection are in web applications. I gained hands-on experience in testing roles, permissions, and spotting potential vulnerabilities. Writing policies deepened my understanding of GDPR and user rights. Overall, I now better appreciate both the technical and ethical responsibilities of secure software development.

## 4. Logbook <a name="logbook"></a>
Logook link: https://github.com/supaizjy0321/Cybersecurity-and-data-privacy---Spring-2025/blob/main/README.md


 - Total Hours Studied: 83.5 hours
Hours by Topic:
 - Booking System: 54.0 hours
 - PortSwigger: 16.5 hours
 - Cisco - Introduction to Cybersecurity: 7.0 hours
 - Final assignment: 3.0 hours
 - Other (e.g., general lectures): 3.0 hours

##### Tracking my progress in a logbook can be a great way to build a sense of accomplishment. It’s amazing how seeing all the hours and effort I’ve put in helps highlight your growth over time
