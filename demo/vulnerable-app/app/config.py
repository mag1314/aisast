"""Application configuration."""
import os

SECRET_KEY = "Acme-Pr0d-Flask-K3y-9f8e7d6c5b4a"
JWT_SECRET = os.environ.get("JWT_SECRET", "dev")
PARTNER_HOST = "api.partner.example"

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_REGION = "us-east-1"

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///acme.db")
PASSWORD_MIN_LENGTH = 10
PASSWORD_FIELD = "password"
