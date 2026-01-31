try:
    # Import configuration first to catch any errors early.
    from config import REDIS_HOST, REDIS_PORT, ENCRYPTION_KEY, AUTH_TOKENS_KEY
except (ValueError, ImportError) as e:
    print(f"FATAL: Could not start the application. Configuration error: {e}")
    exit(1)

import uuid
import os
import redis
import hashlib
from functools import wraps
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)


# --- Setup ---

# Establish a connection to Redis
# decode_responses=True makes working with auth tokens easier. We will use a
# separate client for encrypted data.
try:
    # Client for general use (string data)
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
    # Client for raw encrypted data
    redis_raw_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=False)
    redis_client.ping()
    print("Successfully connected to Redis.")
except redis.exceptions.ConnectionError as e:
    print(f"Error connecting to Redis: {e}")
    # In a real app, you might want to exit or have a retry mechanism.
    redis_client = None
    redis_raw_client = None

# AES-GCM requires a 12-byte nonce for each encryption operation.
AES_NONCE_BYTES = 12
# The GCM authentication tag is 16 bytes (128 bits) long.
AES_TAG_BYTES = 16


# --- Authentication & Authorization ---

def provision_sample_tokens():
    """
    For demonstration purposes, this function creates a few sample API tokens
    with different roles if they don't already exist. In a real system,
    token provisioning would be a secure, managed process.
    """
    if not redis_client or redis_client.hlen(AUTH_TOKENS_KEY) > 0:
        return

    print("Provisioning sample API tokens for demonstration...")
    # A token that can only write (tokenize)
    writer_token = "writer-token-abc-123"
    # A token that can only read (detokenize)
    reader_token = "reader-token-def-456"
    # A token that can do both
    admin_token = "admin-token-xyz-789"
    
    tokens = {
        writer_token: "writer",
        reader_token: "reader",
        admin_token: "writer,reader"
    }
    
    redis_client.hset(AUTH_TOKENS_KEY, mapping=tokens)
    print("Sample tokens have been created.")
    print(f"  Writer Token: {writer_token}")
    print(f"  Reader Token: {reader_token}")
    print(f"  Admin Token:  {admin_token}")


def require_auth(required_role: str):
    """
    Decorator to enforce authentication and authorization for an endpoint.
    Checks for a valid Bearer token and the required role.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not redis_client:
                 return jsonify({"error": "System not available. Cannot connect to data store."}), 503

            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({"error": "Authorization header is missing"}), 401

            try:
                auth_type, token = auth_header.split()
                if auth_type.lower() != 'bearer':
                    return jsonify({"error": "Invalid authorization type. Use 'Bearer'."}), 401
            except ValueError:
                return jsonify({"error": "Invalid authorization header format"}), 401

            # Check if the token is valid and get its roles
            roles_str = redis_client.hget(AUTH_TOKENS_KEY, token)
            if not roles_str:
                return jsonify({"error": "Unauthorized: Invalid token"}), 401

            # Check if the token has the required role
            user_roles = {role.strip() for role in roles_str.split(',')}
            if required_role not in user_roles:
                return jsonify({"error": f"Forbidden: Token does not have '{required_role}' role"}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Encryption & Utility Functions ---

def encrypt(data: str) -> bytes:
    """Encrypts a string using AES-GCM and returns the nonce + ciphertext + tag."""
    aesgcm = AESGCM(ENCRYPTION_KEY)
    nonce = os.urandom(AES_NONCE_BYTES)
    ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
    return nonce + ciphertext

def decrypt(encrypted_data: bytes) -> str:
    """Decrypts data encrypted by the `encrypt` function."""
    aesgcm = AESGCM(ENCRYPTION_KEY)
    nonce = encrypted_data[:AES_NONCE_BYTES]
    ciphertext = encrypted_data[AES_NONCE_BYTES:]
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_bytes.decode('utf-8')

def generate_token():
    """Generates a simple, unique data token."""
    return str(uuid.uuid4()).replace('-', '')[:7]

def get_value_hash(original_value: str) -> str:
    """Calculates the SHA256 hash of a string for idempotency checks."""
    return hashlib.sha256(original_value.encode('utf-8')).hexdigest()

# --- Endpoints ---

@app.route('/tokenize', methods=['POST'])
@require_auth('writer')
def tokenize_data():
    """
    Endpoint to tokenize data. Stores original values encrypted in Redis
    and returns corresponding tokens. This operation is idempotent.
    Requires 'writer' role.
    """
    if not request.is_json:
        return jsonify({"error": "Missing or non-JSON payload"}), 400

    payload = request.get_json()
    req_id = payload.get('id')
    data = payload.get('data')

    if not req_id or not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid request format. Must contain 'id' and 'data' (object)."}), 400

    response_data = {}
    for field_key, original_value in data.items():
        if not isinstance(original_value, str):
            response_data[field_key] = "ERR_NON_STRING_VALUE"
            continue

        value_hash = get_value_hash(original_value)
        token = redis_client.get(f"val:{value_hash}")

        if token:
            response_data[field_key] = token
        else:
            token = generate_token()
            encrypted_value = encrypt(original_value)

            pipe = redis_raw_client.pipeline()
            pipe.set(f"tok:{token}", encrypted_value)
            # Use the string-decoded client for the value hash -> token mapping
            pipe.set(f"val:{value_hash}", token)
            pipe.execute()

            response_data[field_key] = token
    
    return jsonify({
        "id": req_id,
        "data": response_data
    }), 201


@app.route('/detokenize', methods=['POST'])
@require_auth('reader')
def detokenize_data():
    """
    Endpoint to detokenize data. Looks up tokens in Redis and returns
    original decrypted values. Requires 'reader' role.
    """
    if not request.is_json:
        return jsonify({"error": "Missing or non-JSON payload"}), 400

    payload = request.get_json()
    req_id = payload.get('id')
    data = payload.get('data')

    if not req_id or not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid request format. Must contain 'id' and 'data' (object)."}), 400

    response_data = {}
    for field_key, token in data.items():
        if not isinstance(token, str):
            response_data[field_key] = {"found": False, "value": "ERR_INVALID_TOKEN_FORMAT"}
            continue
            
        encrypted_value = redis_raw_client.get(f"tok:{token}")
        
        if encrypted_value:
            try:
                original_value = decrypt(encrypted_value)
                response_data[field_key] = {"found": True, "value": original_value}
            except Exception as e:
                print(f"Decryption error for token {token}: {e}")
                response_data[field_key] = {"found": False, "value": "ERR_DECRYPTION_FAILED"}
        else:
            response_data[field_key] = {"found": False, "value": ""}

    return jsonify({
        "id": req_id,
        "data": response_data
    }), 200

# --- Run the App ---
if __name__ == '__main__':
    # NOTE: In a production deployment, use a production-grade WSGI server
    # (like Gunicorn or uWSGI) and terminate SSL/TLS at a load balancer.
    if redis_client:
        provision_sample_tokens()
    app.run(debug=True, port=8008)