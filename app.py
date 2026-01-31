import os
import uuid
import hashlib
import logging
from typing import Dict, Optional, Union, Tuple
from functools import wraps

import redis
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ValidationError, Field

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Configuration Loading ---
try:
    from config import REDIS_HOST, REDIS_PORT, ENCRYPTION_KEY, AUTH_TOKENS_KEY
    # In a real scenario with Key Rotation, ENCRYPTION_KEY would be a dictionary or a KMS client
    CURRENT_KEY_ID = "v1"
    KEYS = {CURRENT_KEY_ID: ENCRYPTION_KEY}
except (ValueError, ImportError):
    # Fallback for standalone run without config.py
    REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
    # Dummy key for demo (In production this MUST fail)
    ENCRYPTION_KEY = bytes.fromhex("f0c552b7dfbec317ed8021a08cd7a695bab4c0f4182c6b06e95468076cc677ae")
    AUTH_TOKENS_KEY = "auth:tokens"
    CURRENT_KEY_ID = "v1"
    KEYS = {"v1": ENCRYPTION_KEY}
    logger.warning("Using fallback configuration with HARDCODED key. DO NOT USE IN PRODUCTION.")

app = Flask(__name__)

# --- Pydantic Models (Input Validation) ---

class TokenizeRequest(BaseModel):
    id: str
    # Dict[str, str] enforces that values must be strings. 
    # You can create specific models for Email, CreditCard, etc.
    data: Dict[str, str] 

class DetokenizeRequest(BaseModel):
    id: str
    data: Dict[str, str]

# --- Crypto Manager (Key Rotation Ready) ---

class CryptoManager:
    """Handles encryption and decryption with support for Key Versioning."""
    
    AES_NONCE_BYTES = 12

    def __init__(self, keys: Dict[str, bytes], current_key_id: str):
        self.keys = keys
        self.current_key_id = current_key_id

    def encrypt(self, data: str) -> bytes:
        """
        Format: [KeyID_Len (1b)][KeyID (nb)][Nonce (12b)][Ciphertext (nb)][Tag (16b)]
        Simple version for this POC: [KeyID (2 chars)][Nonce (12b)][Ciphertext]
        Assuming KeyID is always 2 chars for simplicity here.
        """
        key = self.keys[self.current_key_id]
        aesgcm = AESGCM(key)
        nonce = os.urandom(self.AES_NONCE_BYTES)
        ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
        
        # Prepend Key ID to allow rotation support
        # Encoding Key ID as utf-8 bytes
        key_id_bytes = self.current_key_id.encode('utf-8')
        return key_id_bytes + nonce + ciphertext

    def decrypt(self, encrypted_payload: bytes) -> str:
        """Parses the payload, extracts Key ID, finds the key, and decrypts."""
        try:
            # Extract Key ID (assuming fixed 2 chars 'v1' for this demo)
            # In production, use a header byte to specify Key ID length.
            key_id = encrypted_payload[:2].decode('utf-8')
            
            if key_id not in self.keys:
                raise ValueError(f"Unknown Key ID: {key_id}")
            
            key = self.keys[key_id]
            aesgcm = AESGCM(key)
            
            nonce = encrypted_payload[2 : 2 + self.AES_NONCE_BYTES]
            ciphertext = encrypted_payload[2 + self.AES_NONCE_BYTES :]
            
            return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError("Decryption failed")

# --- Service Layer (Business Logic) ---

class VaultService:
    """
    Core business logic. Agnostic of HTTP/Flask. 
    Can be called by gRPC, CLI, or Tests directly.
    """
    def __init__(self, redis_client, redis_raw_client, crypto_manager: CryptoManager):
        self.redis = redis_client
        self.redis_raw = redis_raw_client
        self.crypto = crypto_manager

    def _get_value_hash(self, value: str) -> str:
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    def _generate_token(self) -> str:
        return str(uuid.uuid4()).replace('-', '')[:7]

    def tokenize(self, data: Dict[str, str]) -> Dict[str, str]:
        response = {}
        pipeline = self.redis_raw.pipeline()
        
        # Determine which items need new tokens
        new_entries = {}
        
        for key, value in data.items():
            value_hash = self._get_value_hash(value)
            # Check cache (Blind Index)
            existing_token = self.redis.get(f"val:{value_hash}")
            
            if existing_token:
                response[key] = existing_token
            else:
                token = self._generate_token()
                encrypted_val = self.crypto.encrypt(value)
                
                # Prepare writes
                pipeline.set(f"tok:{token}", encrypted_val)
                pipeline.set(f"val:{value_hash}", token) # Plain text mapping for idempotency
                
                response[key] = token
        
        # Execute batch write
        if pipeline:
            pipeline.execute()
            
        return response

    def detokenize(self, tokens: Dict[str, str]) -> Dict[str, dict]:
        response = {}
        for key, token in tokens.items():
            # Retrieve encrypted bytes
            encrypted_val = self.redis_raw.get(f"tok:{token}")
            
            if not encrypted_val:
                response[key] = {"found": False, "value": ""}
                continue

            try:
                plaintext = self.crypto.decrypt(encrypted_val)
                response[key] = {"found": True, "value": plaintext}
            except ValueError:
                response[key] = {"found": False, "value": "ERR_DECRYPT"}
        
        return response

# --- Infrastructure Setup ---

try:
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
    redis_raw_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=False)
    redis_client.ping()
    
    # Initialize Core Components
    crypto_manager = CryptoManager(KEYS, CURRENT_KEY_ID)
    vault_service = VaultService(redis_client, redis_raw_client, crypto_manager)
    
except redis.exceptions.ConnectionError:
    logger.critical("Redis unavailable. Application cannot start.")
    redis_client = None
    vault_service = None

# --- Decorators ---

def require_auth(required_role: str):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not redis_client:
                 return jsonify({"error": "Service Unavailable"}), 503

            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing or invalid Authorization header"}), 401

            token = auth_header.split(" ")[1]
            roles_str = redis_client.hget(AUTH_TOKENS_KEY, token)
            
            if not roles_str:
                return jsonify({"error": "Invalid token"}), 401

            user_roles = {r.strip() for r in roles_str.split(',')}
            if required_role not in user_roles:
                return jsonify({"error": "Forbidden"}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- API Routes (Adapters) ---

@app.route('/tokenize', methods=['POST'])
@require_auth('writer')
def api_tokenize():
    try:
        # Validate input using Pydantic
        req_model = TokenizeRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": "Validation Error", "details": e.errors()}), 400

    if not vault_service:
        return jsonify({"error": "System Error"}), 500

    # Delegate to Service Layer
    results = vault_service.tokenize(req_model.data)
    
    return jsonify({
        "id": req_model.id,
        "data": results
    }), 201

@app.route('/detokenize', methods=['POST'])
@require_auth('reader')
def api_detokenize():
    try:
        req_model = DetokenizeRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": "Validation Error", "details": e.errors()}), 400

    if not vault_service:
        return jsonify({"error": "System Error"}), 500

    results = vault_service.detokenize(req_model.data)
    
    return jsonify({
        "id": req_model.id,
        "data": results
    }), 200

# --- Init ---
if __name__ == '__main__':
    # Provision dummy tokens only for demo
    if redis_client and redis_client.hlen(AUTH_TOKENS_KEY) == 0:
        redis_client.hset(AUTH_TOKENS_KEY, mapping={
            "writer-token": "writer",
            "reader-token": "reader",
            "admin-token": "writer,reader"
        })
        print("Demo Tokens Created: writer-token, reader-token, admin-token")
        
    app.run(debug=True, port=8008)