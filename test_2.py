import os
import pytest
from fastapi.testclient import TestClient
from project_2 import app, DB_FILE
import jwt

client = TestClient(app)

# Clean up DB before running tests 
@pytest.fixture(autouse=True)
def run_around_tests():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        # Initialize DB and seed keys on startup
    from project_2 import init_db, generate_and_store_key
    init_db()
    generate_and_store_key(is_expired=False)
    generate_and_store_key(is_expired=True)
    yield
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

# send get request and check expected keys
def test_jwks_handler_returns_unexpired_keys():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1 
    # Check that kid is a string representation of an integer
    assert data["keys"][0]["kid"].isdigit()

# send post request and check kid is good key
def test_auth_handler_unexpired():
    response = client.post("/auth", json={"username": "userABC", "password": "password123"})
    assert response.status_code == 200
    token = response.text
    
    # Decode the unverified header
    headers = jwt.get_unverified_header(token)
    assert "kid" in headers
    assert headers["kid"].isdigit()

# send post request to check kid is expired key
def test_auth_handler_expired():
    response = client.post("/auth?expired=true", json={"username": "userABC", "password": "password123"})
    assert response.status_code == 200
    token = response.text
    
    # Decode the unverified header
    headers = jwt.get_unverified_header(token)
    assert "kid" in headers
    assert headers["kid"].isdigit()