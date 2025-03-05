# Project 1: JWKS Server

## Description
This project uses Python to create a RESTful JWKS server. The server uses kid unique identifiers to give public keys and verify JSON Web Tokens. It implements key expiry and authentication endpoints and allows issuing JWTs with expired keys when requested through a query parameter.


## Sources
I used ChatGPT and DeepSeek for guidance in the key generation aspect of the project. I used them to learn how the code can be written. I used the prompt: "Using Python: Implement RSA key pair generation by first creating a private key, then private_pem, and then creating an expiry timestamp for each key." This prompt depicted a close code that was needed in the assignment, but it wasn't perfect. I mainly used the output for guidance and inspiration for my code.


## Installation Instructions
-	Download the project folder with the LICENSE, gradebot.exe and the project.py files. 
-	Open a terminal.
-	Change directories to the folder. 
-	Run the project.py file by running ```python .\project.py```
-	If there are any errors, install libraries by using the command ```pip install <library_name>```
-	Rerun file with ```python .\project.py```
-	Leave this console open. The program should now be running.
-	In a separate console, change directories to the folder (where the grade bot is being stored).
-	Run the grade bot using the command ```gradebot.exe project1```
-	The command should execute like the screenshot provided. 
