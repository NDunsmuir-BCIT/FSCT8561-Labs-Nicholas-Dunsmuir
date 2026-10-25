# run once before starting the server, creates a user in users.json
import sys
from getpass import getpass

from auth import add_user
from config import MAX_PASSWORD_LEN, USERNAME_RE


def main():
     # check the username format to make sure it matches
    if len(sys.argv) != 2 or not USERNAME_RE.fullmatch(sys.argv[1]):
        print("Usage: python setup_users.py <username>   (1-32 letters, digits or _)")
        return 1
    username = sys.argv[1]
    # getpass hides the password while typing
    password = getpass("New password (min 8 characters): ")
    # min 8 so weak passwords aren't allowed, max 128 to match the server
    if len(password) < 8 or len(password) > MAX_PASSWORD_LEN:
        print("Password must be 8-128 characters.")
        return 1
    # ask twice so a typo doesn't lock the user out
    if password != getpass("Repeat password: "):
        print("Passwords did not match.")
        return 1
    # password gets salted and hashed
    secret, uri = add_user(username, password)
    print(f"\nUser '{username}' saved to users.json (salted PBKDF2 hash).")
    print("TOTP secret :", secret)
    print("Provisioning:", uri)
    # users.json has the hashes and TOTP secrets so it stays out of GitHub
    print("Keep users.json private. It is listed in .gitignore.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
