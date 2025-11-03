# auth/hash_utils.py
import os
from argon2 import PasswordHasher, exceptions
from dotenv import load_dotenv

load_dotenv()

# Configure Argon2 (you can tune these later)
ph = PasswordHasher(
    time_cost=2,        # Number of iterations
    memory_cost=65536,  # 64 MB memory
    parallelism=2,      # Threads
    hash_len=32
)

def get_pepper():
    return os.getenv("PEPPER", "")

def hash_password(password: str) -> str:
    pepper = get_pepper()
    return ph.hash(password + pepper)

def verify_password(stored_hash: str, password: str) -> bool:
    pepper = get_pepper()
    try:
        return ph.verify(stored_hash, password + pepper)
    except exceptions.VerifyMismatchError:
        return False
