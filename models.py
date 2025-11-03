# models.py
from sqlalchemy import Column, Integer, String, DateTime, Boolean, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
import os

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    password_hash_algo = Column(String, default="argon2id")
    password_last_changed = Column(DateTime, default=datetime.datetime.utcnow)
    force_password_reset = Column(Boolean, default=False)
    mfa_totp_secret = Column(String, nullable=True)  # NEW: store base32 TOTP secret

# database setup (SQLite)
DB_PATH = os.getenv("DATABASE_URL", "sqlite:///instance/app.db")
engine = create_engine(DB_PATH, echo=True)
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(engine)
