# it prints the current OTP from users.json
import sys

import pyotp

from auth import AuthError, load_users

def main():
    if len(sys.argv) != 2:
        print("Usage: python show_otp.py <username>")
        return 1
    try:
        users = load_users()
    except AuthError as err:
        print("Error:", err)
        return 1
    record = users.get(sys.argv[1])
    if record is None:
        print("No such user.")
        return 1
    print(pyotp.TOTP(record["totp_secret"]).now())
    return 0


if __name__ == "__main__":
    sys.exit(main())
