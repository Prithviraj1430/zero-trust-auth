# app.py — single-file app with register, login, mfa/setup, mfa/enable
import os
import datetime
import base64
from io import BytesIO

from flask import Flask, request, jsonify
from dotenv import load_dotenv

# DB / ORM
from sqlalchemy import Column, Integer, String, DateTime, Boolean, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Password hashing
from argon2 import PasswordHasher, exceptions

# TOTP
import pyotp

# Optional QR generation
try:
    import qrcode
    QR_AVAILABLE = True
except Exception:
    QR_AVAILABLE = False

# load .env
load_dotenv()

# Config
PEPPER = os.getenv("PEPPER", "")
DB_URL = os.getenv("DATABASE_URL", "sqlite:///instance/app.db")
ISSUER_NAME = os.getenv("MFA_ISSUER", "ZeroTrustAuth")

# Argon2 hasher (tune in production)
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2, hash_len=32)

# SQLAlchemy setup
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    password_hash_algo = Column(String, default="argon2id")
    password_last_changed = Column(DateTime, default=datetime.datetime.utcnow)
    force_password_reset = Column(Boolean, default=False)
    mfa_totp_secret = Column(String, nullable=True)

engine = create_engine(DB_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

# Flask app
app = Flask(__name__)

# Simple helper funcs for hashing
def hash_password(plain: str) -> str:
    combined = plain + PEPPER
    return ph.hash(combined)

def verify_password_and_maybe_rehash(stored_hash: str, plain: str):
    """
    Returns (valid: bool, new_hash_or_None: str|None)
    """
    combined = plain + PEPPER
    try:
        valid = ph.verify(stored_hash, combined)
        new_hash = None
        if ph.check_needs_rehash(stored_hash):
            new_hash = ph.hash(combined)
        return True, new_hash
    except exceptions.VerifyMismatchError:
        return False, None
    except Exception:
        return False, None

# DB session helper (simple)
def get_db():
    return SessionLocal()

@app.route("/")
def home():
    return jsonify({"message": "Zero Trust Auth API running 🚀"})

# Register
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    db = get_db()
    if db.query(User).filter(User.email == email).first():
        return jsonify({"error": "User already exists"}), 400

    user = User(email=email, password_hash=hash_password(password))
    db.add(user)
    db.commit()
    return jsonify({"message": "User registered successfully!"}), 201

# Login (password first; requires token if MFA enabled)
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")
    token = data.get("token")  # optional

    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    db = get_db()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    valid, new_hash = verify_password_and_maybe_rehash(user.password_hash, password)
    if not valid:
        return jsonify({"error": "Invalid credentials"}), 401

    # persist rehash if needed
    if new_hash:
        user.password_hash = new_hash
        db.add(user)
        db.commit()

    # if user enabled MFA, require token
    if user.mfa_totp_secret:
        if not token:
            return jsonify({"mfa_required": True, "message": "MFA token required"}), 200
        totp = pyotp.TOTP(user.mfa_totp_secret)
        if not totp.verify(token, valid_window=1):
            return jsonify({"error": "Invalid MFA token"}), 401

    # SUCCESS — in real app issue session / JWT here
    return jsonify({"message": "Login successful!"}), 200

# MFA setup — returns secret + provisioning_uri + optional base64 QR
@app.route("/mfa/setup", methods=["POST"])
def mfa_setup():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    if not email:
        return jsonify({"error": "email required"}), 400

    db = get_db()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return jsonify({"error": "user not found"}), 404

    # If user already has secret return it (allow re-setup)
    secret = user.mfa_totp_secret or pyotp.random_base32()
    provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER_NAME)

    qr_b64 = None
    if QR_AVAILABLE:
        try:
            img = qrcode.make(provisioning_uri)
            buf = BytesIO()
            img.save(buf, format="PNG")
            buf.seek(0)
            qr_b64 = base64.b64encode(buf.read()).decode("utf-8")
        except Exception:
            qr_b64 = None

    return jsonify({"secret": secret, "provisioning_uri": provisioning_uri, "qr_b64": qr_b64}), 200

# MFA enable — verify first OTP and persist secret
@app.route("/mfa/enable", methods=["POST"])
def mfa_enable():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    secret = data.get("secret")
    token = data.get("token")
    if not all([email, secret, token]):
        return jsonify({"error": "email, secret, token required"}), 400

    db = get_db()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return jsonify({"error": "user not found"}), 404

    totp = pyotp.TOTP(secret)
    if totp.verify(token, valid_window=1):
        user.mfa_totp_secret = secret
        db.add(user)
        db.commit()
        return jsonify({"message": "MFA enabled"}), 200
    else:
        return jsonify({"error": "invalid token"}), 400


# DEV-ONLY: returns current OTP for a user (remove before sharing/pushing)
@app.route("/debug/otp", methods=["POST"])
def debug_otp():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    if not email:
        return jsonify({"error": "email required"}), 400
    db = get_db()
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.mfa_totp_secret:
        return jsonify({"error": "user not found or MFA not enabled"}), 404
    # generate current OTP
    current = pyotp.TOTP(user.mfa_totp_secret).now()
    return jsonify({"otp": current}), 200

if __name__ == "__main__":
    # ensure instance folder exists for sqlite file
    os.makedirs("instance", exist_ok=True)
    app.run(debug=True)
