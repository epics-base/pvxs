import base64
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, request, jsonify, Response
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

# --- Config (env overridable) ---
PORT = int(os.getenv("PORT", "8080"))
DEFAULT_ISS = os.getenv("ISSUER", "http://localhost:8080/default")
DEFAULT_AUD = os.getenv("DEFAULT_AUDIENCE", "default")
DEFAULT_EXP_SECS = int(os.getenv("DEFAULT_EXP_SECS", "3600"))
ALGO = os.getenv("ALGO", "RS256")  # RS256 (default) or HS256
KEY_DIR = Path(os.getenv("KEY_DIR", "/data/keys"))
KID = os.getenv("KID", "demo-key-1")
HS_SECRET = os.getenv("HS_SECRET", "dev-secret-change-me")  # only used if ALGO=HS256

# --- Keys (ephemeral by default; files used only if writable and present) ---
_priv_key = None
_pub_key = None

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _ensure_keys():
    """Generate or load RSA keys for RS256. HS256 uses HS_SECRET."""
    global _priv_key, _pub_key
    if ALGO.upper() == "HS256":
        return  # nothing to do

    KEY_DIR.mkdir(parents=True, exist_ok=True)
    priv_path = KEY_DIR / "id_rsa.pem"
    pub_path = KEY_DIR / "id_rsa.pub"

    if priv_path.exists() and pub_path.exists():
        _priv_key = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        _pub_key = serialization.load_pem_public_key(pub_path.read_bytes())
        return

    # Generate ephemeral RSA keypair
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()

    _priv_key = key
    _pub_key = pub

    # Best-effort write (ok if it fails; we remain in-memory)
    try:
        priv_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        priv_path.write_bytes(priv_bytes)
        pub_path.write_bytes(pub_bytes)
    except Exception:
        pass

def _current_priv_key():
    return HS_SECRET if ALGO.upper() == "HS256" else _priv_key

def _current_pub_key():
    return HS_SECRET if ALGO.upper() == "HS256" else _pub_key

def _rsa_jwk():
    if ALGO.upper() == "HS256" or _pub_key is None:
        return []
    nums = _pub_key.public_numbers()
    n = _b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big"))
    e = _b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))
    return [{
        "kty": "RSA",
        "kid": KID,
        "alg": "RS256",
        "use": "sig",
        "n": n,
        "e": e,
    }]

# Initialize keys at import
_ensure_keys()

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

# Issue: GET /default/token?sub=client&password=secret[&aud=...&iss=...&exp_secs=...]
@app.get("/default/token")
def issue_token():
    sub = request.args.get("sub")
    pwd = request.args.get("password")
    if not sub:
        return jsonify(error="missing 'sub'"), 400
    if pwd != "secret":
        return "Forbidden", 403

    aud = request.args.get("aud", DEFAULT_AUD)
    iss = request.args.get("iss", DEFAULT_ISS)
    exp_secs = int(request.args.get("exp_secs", DEFAULT_EXP_SECS))

    now = datetime.now(timezone.utc)
    claims = {
        "sub": sub,
        "iss": iss,
        "aud": aud,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=exp_secs)).timestamp()),
        "jti": str(uuid.uuid4()),
    }

    headers = {"kid": KID, "typ": "JWT"}
    token = jwt.encode(
        claims,
        _current_priv_key(),
        algorithm=ALGO,
        headers=headers,
    )
    # Return RAW token (text/plain), not JSON
    return Response(token, mimetype="text/plain")

# Verify: GET /default/verify?token=... [&expected_iss=...][&expected_aud=...]
@app.get("/default/verify")
def verify_token():
    token = request.args.get("token")
    if not token:
        return jsonify(valid=False, error="missing 'token'"), 400

    expected_iss = request.args.get("expected_iss", DEFAULT_ISS)
    expected_aud = request.args.get("expected_aud")  # optional

    options = {
        "require": ["exp", "iat", "nbf", "iss", "sub"],
        "verify_aud": bool(expected_aud),
    }

    try:
        decoded = jwt.decode(
            token,
            _current_pub_key(),
            algorithms=[ALGO],
            issuer=expected_iss,
            audience=expected_aud if expected_aud else None,
            options=options,
        )
        header = jwt.get_unverified_header(token)
        return jsonify(valid=True, header=header, claims=decoded)
    except Exception as e:
        return jsonify(valid=False, error=str(e))

# JWKS
@app.get("/.well-known/jwks.json")
@app.get("/default/jwks")
def jwks():
    return jsonify({"keys": _rsa_jwk()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
