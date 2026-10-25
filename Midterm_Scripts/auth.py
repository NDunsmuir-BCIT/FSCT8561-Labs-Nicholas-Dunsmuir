import hashlib
import hmac
import json
import os

import pyotp

from config import OTP_RE, USERS_FILE
# pbkdf2 with 200,000 rounds slows down brute force attacks or offline guessing of passwords
ITERATIONS = 200000


class AuthError(Exception):
    pass


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)


def load_users(path=USERS_FILE):
    try:
        with open(path) as f:
            users = json.load(f)
    except (OSError, ValueError):
        raise AuthError("users.json missing or unreadable")
    if not users:
        raise AuthError("users.json has no users")
    return users


def add_user(username, password, path=USERS_FILE):
    try:
        users = load_users(path)
    except AuthError:
        users = {}

# random salt for each user so a duplicate hash isnt used
    salt = os.urandom(16)
    secret = pyotp.random_base32()
    users[username] = {
        "salt": salt.hex(),
        "password_hash": hash_password(password, salt).hex(),
        "totp_secret": secret,
    }
    with open(path, "w") as f:
        json.dump(users, f, indent=2)

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=username, issuer_name="Operation-Sentinel")
    return secret, uri


def verify_password(users, username, password):
    user = users.get(username)
    if user is None:
        # still run a hash for unknown users so the response time is the same 
        hash_password(password, bytes(16))
        return False
    try:
        salt = bytes.fromhex(user["salt"])
        stored = bytes.fromhex(user["password_hash"])
    except (KeyError, ValueError):
        return False
    return hmac.compare_digest(hash_password(password, salt), stored)


def verify_otp(users, username, otp):
    user = users.get(username)
    # reject anything that isn't exactly 6 digits
    if user is None or not OTP_RE.fullmatch(otp):
        return False
    # pyotp only accepts the code for the current 30 second window
    return pyotp.TOTP(user["totp_secret"]).verify(otp)