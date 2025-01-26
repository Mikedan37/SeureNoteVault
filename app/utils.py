import pyotp
from itsdangerous import URLSafeTimedSerializer
import os
import csv
from io import StringIO

def generate_totp_secret():
    return pyotp.random_base32()

def generate_reset_token(user_id, secret_key="your-secret-key"):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(user_id, salt="password-reset-salt")

def generate_webauthn_challenge():
    return os.urandom(32).hex()

def convert_to_csv(data):
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=data[0].keys())
    writer.writeheader()
    writer.writerows(data)
    return output.getvalue()