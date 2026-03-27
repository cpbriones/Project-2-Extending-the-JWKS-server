""" Cristobal Briones cpb0128
CSCE 3550 Project 2: Extending the JWKS server
Using python and FastAPI this project implements a jwks server with key expiration and jwt signing. 
integrating SQLite and emphasizing secure database interactions preventing malicious SQL query manipulation 

"""

import time
import sqlite3
from fastapi import FastAPI, Response, Request
import jwt
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import uvicorn

app = FastAPI()

# SQLite storage 
DB_FILE = "totally_not_my_privateKeys.db"

# initialize sqlite database and creates keys table if it doesn't exist
def init_db():
  
    # connect to the SQLite database file
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Table schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
            )
    ''')
    conn.commit()
    conn.close()

# generate RSA key pair and store 
def generate_and_store_key(is_expired: bool = False) -> None:
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Serialize the key to a format on save
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Calculate expiration time
    expiry = int(time.time()) - 3600 if is_expired else int(time.time()) + 3600
    
    # Connect to DB and use parameterized query to prevent SQL injection
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, expiry))
    conn.commit()
    conn.close()

# Initialize DB
init_db()
# Initialize keys in DB
generate_and_store_key(is_expired=False)
generate_and_store_key(is_expired=True)

@app.get('/.well-known/jwks.json')
@app.get('/jwks')
# Filters out expired keys. returns JSON with valid keys 
def jwks_handler():
    current_time = int(time.time())
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Read all valid private keys from the DB
    cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (current_time,))
    rows = cursor.fetchall()
    conn.close()
    
    valid_keys = []
    for row in rows:
        kid, key_blob = row
        
        # Deserialize the key on read
        private_key = serialization.load_pem_private_key(
            key_blob,
            password=None,
            backend=default_backend()
        )
        
        # Converts public key to JWK format
        public_key = private_key.public_key()
        jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)

        # metadata for JWK
        jwk["alg"] = "RS256"
        jwk["use"] = "sig"
        jwk["kid"] = str(kid)
        valid_keys.append(jwk)
        
    return {"keys": valid_keys}

@app.post('/auth')
async def auth_handler(request: Request, expired: str | None = None):
    
    is_expired_req = expired is not None
    current_time = int(time.time())
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Read key based on expired query parameter
    if is_expired_req:
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1", (current_time,))
    else:
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1", (current_time,))
        
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return Response(content="No valid key found", media_type="text/plain", status_code=500)
        
    kid, key_blob, exp = row
    
    # Deserialize the key into a usable Python object
    private_key = serialization.load_pem_private_key(
        key_blob,
        password=None,
        backend=default_backend()
    )
    
    # Create JWT payload
    payload = {
        "sub": "mock-user",
        "exp": exp,
        "iat": current_time
    }
    
    # Sign the JWT with the selected key's private key
    token = jwt.encode(
        payload, 
        private_key,
        algorithm="RS256", 
        headers={"kid": str(kid)}
    )
    
    # Return raw text string
    return Response(content=token, media_type="text/plain")

if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=8080)



""" AI Prompts used for development:
These prompts helped me implement the fastapi framework, RSA key generation, JWK conversion, and JWT signing.

fastapi vs flask for jwks server
fastapi jwks server creation
RSA key generation python
Generate RSA key pair in Python using cryptography library
RSA key JWK conversion
to_jwk to return Python dictionary instead of a string
jwt payload python
return jwt as raw text string fastapi
fastapi test client python
python test coverage tools
sqlite python fastapi implementation
sqlite parameterized queries python
serialize RSA key to PEM format python
sqlite database test pytest
"""