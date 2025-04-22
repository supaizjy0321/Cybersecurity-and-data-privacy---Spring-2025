# Table of contents
1. [Cisco - Introduction to Cybersecurity](#cisco)
2. [PortSwigger](#portswigger)
    1. [Dashboard of all the labs](#dashboard)
3. [Another paragraph](#paragraph2)

## 1. Cisco - Introduction to Cybersecurity <a name="cisco"></a>
<img src="https://github.com/supaizjy0321/Cybersecurity-and-data-privacy---Spring-2025/blob/main/cisco%20score.png" width="800"/>

 - Reflection: This introductory course takes me inside the world of cybersecurity. I have learned cybersecurity basics to protesct my personal digital life. Also, I have learned the biggest securtiy challenges companies, goverments, and educational institutions face today. Sometimes the exam wss tricky for me, because I mixed some professional terms. But this course worthes learning, it's a good start for cybersecurity world.

## PortSwigger <a name="portswigger"></a>
The first paragraph text



Topic SQL injection
- SQL injection vulnerability in WHERE clause allowing retrieval of hidden data → Reflection: The first step is to use Burp Suite to check the request if I select “Gift”, then it’s easy to get the parameter of category. released = 1 means the released product, so I need to also add unleased product. I learned from the material I can use category=Gifts'+OR+1=1-- for all the product in Gift category.
- SQL injection vulnerability allowing login bypass → Reflection: This lab is solve due to the vulnerability allowing login bypass. I can use the SQL comment sequence -- to remove the password check from the WHERE clause of the query.

Topic Authentication
- Username enumeration via different responses → Reflection: In this lab, I get the candidate usernames and passwords. Then I try username in the Burp Intruder, the special timeout let me find a valid username. Next time, I use the valid username and try all the candidate passwords. To oberserve the timeout to find the password I want. Finally, login in with the valid username and password.
- Password reset broken logic → Reflection: The vulnerability is from the password reset, so I can utilize it. First, I click forget the password and enter uesrname wiener. After clicking the email client, I click the link in email and reset my password. The password reset function does not validate the reset token. By removing the token and changing the username, I can reset another carlos’s password.

Topic Access control
- Unprotected admin functionality → Reflection: At first I add /robots.txt to the lab URL. Becaue this lab has an unprotected admin panel. Then I add /administrator-panel to get the admin panel. Finally, it is easy to choose carlos to delete.
- User role can be modified in user profile → Reflection: From the lab content, I get that the admin panel can only be accessible to loggin-in user with a roleid of 2. So at first, I login with the supplied credentials: wiener:peter and then update the email address. Send the email submission request to Repeater, and change roleid of 1 to 2. Once it is changed to 2, browse /admin to delete the user carlos.

 

### Dashboard of all the labs <a name="dashboard"></a>
This is a sub paragraph, formatted in heading 3 style

## Another paragraph <a name="paragraph2"></a>
The second paragraph text

<img src="https://github.com/supaizjy0321/Cybersecurity-and-data-privacy---Spring-2025/blob/main/cisco%20score.png" width="800"/>

https://github.com/supaizjy0321/Cybersecurity-and-data-privacy---Spring-2025/blob/main/cisco%20score.png
