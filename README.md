# 🔐 Zero Trust Authentication System  
A simple yet secure **Zero Trust Authentication** demo built with **Flask**, **Argon2id**, and **TOTP-based MFA**.  
Implements password hashing, multi-factor authentication, and secure secret management — built for educational Zero Trust projects.

![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-lightgrey?logo=flask)
![Security](https://img.shields.io/badge/Security-Zero%20Trust-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Active-success)



🚀 Features

✅ Register new users with Argon2id-hashed passwords
✅ Secure login verification with rehash-on-login
✅ MFA setup with QR code (Google Authenticator or Authy)
✅ MFA verification using TOTP codes
✅ Environment-based PEPPER for added hash security
✅ Lightweight SQLite storage
✅ Clean and commented code, easy to extend

🧰 Tech Stack
Component	Technology
Language	Python 3.10+
Framework	Flask
Hashing	Argon2id (argon2-cffi)
Database	SQLite + SQLAlchemy
MFA	pyotp
QR Generation	qrcode[pil] (optional)
⚙️ Setup & Installation
1️⃣ Clone the repository
git clone https://github.com/YOUR_GITHUB_USERNAME/zero-trust-auth.git
cd zero-trust-auth

2️⃣ Create a virtual environment
python -m venv venv
# On Windows PowerShell
venv\Scripts\activate

3️⃣ Install dependencies
pip install -r requirements.txt

4️⃣ Create .env file

Create a file named .env in your project folder:

FLASK_APP=app.py
FLASK_ENV=development
PEPPER=MySuperSecretPepper123!  # Change this before using

5️⃣ Run the app
python app.py


✅ Flask will start on http://127.0.0.1:5000

🔐 API Endpoints
1. Home
GET /
→ { "message": "Zero Trust Auth API running 🚀" }

2. Register
POST /register
Body: { "email": "test@example.com", "password": "mypassword123" }
→ { "message": "User registered successfully!" }

3. Login
POST /login
Body: { "email": "test@example.com", "password": "mypassword123" }

# If MFA is enabled:
→ { "mfa_required": true, "message": "MFA token required" }

# With MFA token:
Body: { "email": "test@example.com", "password": "mypassword123", "token": "123456" }
→ { "message": "Login successful!" }

4. Setup MFA
POST /mfa/setup
Body: { "email": "test@example.com" }
→ { "secret": "...", "provisioning_uri": "...", "qr_b64": "..." }

5. Enable MFA
POST /mfa/enable
Body: { "email": "test@example.com", "secret": "...", "token": "123456" }
→ { "message": "MFA enabled" }

📸 QR Setup Example (PowerShell)
$r = Invoke-WebRequest -Uri "http://127.0.0.1:5000/mfa/setup" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"email":"test@example.com"}'
$json = $r.Content | ConvertFrom-Json
[System.IO.File]::WriteAllBytes("mfa_qr.png",[Convert]::FromBase64String($json.qr_b64))
ii .\mfa_qr.png


Scan the QR in Google Authenticator or Authy and verify using /mfa/enable.

🔍 Testing in PowerShell
Register
(Invoke-WebRequest -Uri "http://127.0.0.1:5000/register" `
  -Method POST -ContentType "application/json" `
  -Body '{"email":"test@example.com","password":"mypassword123"}').Content

Login
(Invoke-WebRequest -Uri "http://127.0.0.1:5000/login" `
  -Method POST -ContentType "application/json" `
  -Body '{"email":"test@example.com","password":"mypassword123"}').Content

🔑 Security Notes

Never commit your .env file or secrets to GitHub.

Use unique, random PEPPER values in production.

Remove /debug/otp endpoint if you added it for local testing.

Do not use Flask’s built-in server for production — use Gunicorn or uWSGI.

Regularly tune Argon2 parameters as hardware improves.

🧠 Future Enhancements

✅ JWT-based session tokens

✅ Role-based access control (RBAC)

✅ WebAuthn / FIDO2 support

✅ Database encryption at rest

✅ Rate limiting and anomaly detection

👨‍💻 Contributors

Your Name — Developer

Instructor — Project Reviewer

📝 License

This project is for educational purposes as part of a Zero Trust Security assignment.
Feel free to reuse or extend with proper credit.