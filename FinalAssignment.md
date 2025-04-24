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
  
3. [Another paragraph](#paragraph2)

## 1. Cisco - Introduction to Cybersecurity <a name="cisco"></a>
<img src="https://github.com/supaizjy0321/Cybersecurity-and-data-privacy---Spring-2025/blob/main/cisco%20score.png" width="800"/>

 - Reflection: This introductory course takes me inside the world of cybersecurity. I have learned cybersecurity basics to protesct my personal digital life. Also, I have learned the biggest securtiy challenges companies, goverments, and educational institutions face today. Sometimes the exam wss tricky for me, because I mixed some professional terms. But this course worthes learning, it's a good start for cybersecurity world.

## PortSwigger <a name="portswigger"></a>
### Dashboard of all the labs <a name="dashboard"></a>
This is a sub paragraph, formatted in heading 3 style

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

### Topic OS command injection <a name="oscommandinjection"></a>
 - OS command injection, simple case -> use burp to check product stock

### Topic Path traversal <a name="pathtranersal"></a>
 - File path traversal, simple case -> forward the product then find path traversal vulnerability

### Topic Cross-site scripting <a name="crosssitescripting"></a>
 - Reflected XSS into HTML context with nothing encoded -> solve the majority of our XSS labs by invoking alert() in a simulated victim's browser
 - Stored XSS into HTML context with nothing encoded -> still using alert() but stored XSS
 - 
   




Topic Access control
- Unprotected admin functionality → Reflection: At first I add /robots.txt to the lab URL. Becaue this lab has an unprotected admin panel. Then I add /administrator-panel to get the admin panel. Finally, it is easy to choose carlos to delete.
- User role can be modified in user profile → Reflection: From the lab content, I get that the admin panel can only be accessible to loggin-in user with a roleid of 2. So at first, I login with the supplied credentials: wiener:peter and then update the email address. Send the email submission request to Repeater, and change roleid of 1 to 2. Once it is changed to 2, browse /admin to delete the user carlos.

 



## Another paragraph <a name="paragraph2"></a>
The second paragraph text

<img src="https://github.com/supaizjy0321/Cybersecurity-and-data-privacy---Spring-2025/blob/main/cisco%20score.png" width="800"/>

https://github.com/supaizjy0321/Cybersecurity-and-data-privacy---Spring-2025/blob/main/cisco%20score.png
