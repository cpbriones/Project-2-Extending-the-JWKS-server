# Project-2-Extending-the-JWKS-Server
RESTful JWKS server that provides public keys with unique identifiers (kid) for verifying JSON Web Tokens (JWTs), implements key expiry for enhanced security, includes an authentication endpoint, and handles the issuance of JWTs with expired keys based on a query parameter.

This project uses SQLite Links to an external site., a single-file database, to enhance your JWKS server. SQLite is not a database server, but a serverless database that relies on drivers/libraries in your program to create, read, update, and delete database rows. To utilize SQLite, you'll be modifying your previous project to:

    Create/open a SQLite DB file at start.
    Write your private keys to that file.
    Modify the POST:/auth and GET:/.well-known/jwks.json endpoints to use the database.


# Installation
1. Clone/download project
2. Create virtual environment
   
`python -m venv .venv`

4. Activate virtual environment (windows)
   
`.venv\Scripts\activate`

6. Install dependencies
   
`pip install fastapi uvicorn PyJWT cryptography httpx pytest pytest-cov`

# Testing
1. start server

`python project_2.py`

3. run test suite 

`pytest --cov=project_2 test_2.py`

4. gradebot

`./gradebot.exe project-2 --run="python project_2.py"`
