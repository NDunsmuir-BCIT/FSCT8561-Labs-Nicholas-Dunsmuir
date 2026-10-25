import logging
import socket
import sys

from auth import AuthError, load_users, verify_otp, verify_password
from config import (HOST, IDLE_TIMEOUT, LOG_FILE, MAX_FAILURES, MAX_MESSAGE,
                    MAX_PASSWORD_LEN, OTP_RE, PORT, USERNAME_RE)
from pcap_analyzer import AnalysisError, analyze, to_json_line

# the server remembers where each connection is in the login process
CONNECTED = "CONNECTED"
PASSWORD_OK = "PASSWORD_OK"
AUTHENTICATED = "AUTHENTICATED"

log = logging.getLogger("sentinel")

# security log only gets event names, client address and username
def setup_logging():
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    log.setLevel(logging.INFO)
    for handler in (logging.FileHandler(LOG_FILE), logging.StreamHandler()):
        handler.setFormatter(formatter)
        log.addHandler(handler)


def send_line(conn, text):
    conn.sendall((text + "\n").encode())


def read_message(conn):
    data = b""
    too_long = False
    while True:
        ch = conn.recv(1)
        if ch == b"":
            return None, False
        if ch == b"\n":
            return data, too_long
        # keep reading until the newline but throw away anything past the MAX_MESSAGE limit
        if len(data) >= MAX_MESSAGE:
            too_long = True
        else:
            data += ch


def count_failure(session, event, reply):
    if session["state"] == AUTHENTICATED:
        log.warning("event=%s client=%s user=%s", event, session["client"], session["user"])
        return reply
    
# every failure before login counts towards the lockout, not just wrong passwords
    session["failures"] += 1
    log.warning("event=%s client=%s failures=%d", event, session["client"], session["failures"])

# after 3 failures the connection gets closed
    if session["failures"] >= MAX_FAILURES:
        session["closing"] = True
        log.warning("event=lockout client=%s", session["client"])
        return "ERROR|Locked"
    return reply


def bad_request(session):
    return count_failure(session, "bad_request", "ERROR|Bad request")


def not_allowed(session, command):
    event = "rejected_" + command.lower() + "_in_" + session["state"].lower()
    return count_failure(session, event, "ERROR|Not allowed")


def handle_auth(session, users, parts):
    if session["state"] != CONNECTED:
        return not_allowed(session, "AUTH")
    if len(parts) != 3:
        return bad_request(session)

    username = parts[1]
    password = parts[2]
    # check the fields first so bad input never reaches the hash function or the log
    if not USERNAME_RE.fullmatch(username) or len(password) == 0 or len(password) > MAX_PASSWORD_LEN:
        return bad_request(session)

    if verify_password(users, username, password):
        session["state"] = PASSWORD_OK
        session["user"] = username
        log.info("event=password_ok client=%s user=%s", session["client"], username)
        return "OTP_REQUIRED"
    
# any failure sends the session back to the start to force attackers to redo the password step
    session["state"] = CONNECTED
    session["user"] = None
    # same message for a wrong username or wrong password
    return count_failure(session, "auth_failed user=" + username,
                         "ACCESS_DENIED|Invalid credentials")


def handle_otp(session, users, parts):
    # OTP is only accepted after the password passed
    if session["state"] != PASSWORD_OK:
        return not_allowed(session, "OTP")
    if len(parts) != 2 or not OTP_RE.fullmatch(parts[1]):
        return bad_request(session)

    if verify_otp(users, session["user"], parts[1]):
        session["state"] = AUTHENTICATED
        session["failures"] = 0
        log.info("event=login_success client=%s user=%s", session["client"], session["user"])
        return "ACCESS_GRANTED"

    user = session["user"]
    session["state"] = CONNECTED
    session["user"] = None
    return count_failure(session, "otp_failed user=" + user,
                         "ACCESS_DENIED|Invalid or expired OTP")


def handle_pcap(session, parts):
    # PCAP is the only protected command and only runs after full authentication
    if session["state"] != AUTHENTICATED:
        return not_allowed(session, "PCAP")
    if len(parts) != 2 or parts[1] != "":
        return bad_request(session)

    try:
        # no file path comes from the client and analyze() only opens the fixed PCAP file.
        summary = analyze()
    except AnalysisError as err:
        log.error("event=pcap_failed client=%s user=%s reason=%s",
                  session["client"], session["user"], err)
        # the client only gets a generic error, the real reason only goes in the server log
        return "ERROR|Analysis unavailable"

    log.info("event=pcap_ok client=%s user=%s alerts=%d",
             session["client"], session["user"], len(summary["alerts"]))
    return "OK|" + to_json_line(summary)


def handle_message(session, users, raw):
    try:
        line = raw.decode("utf-8")
    except UnicodeDecodeError:
        return bad_request(session)
    line = line.rstrip("\r")
# control characters are rejected to protect the log format
    has_control_char = any(ord(c) < 32 for c in line)
    if "|" not in line or has_control_char:
        return bad_request(session)
    
# split at most twice so a password that has a | in it stays in one piece
    parts = line.split("|", 2)
    command = parts[0].upper()

    if command == "AUTH":
        return handle_auth(session, users, parts)
    elif command == "OTP":
        return handle_otp(session, users, parts)
    elif command == "PCAP":
        return handle_pcap(session, parts)
    elif command == "EXIT":
        session["closing"] = True
        log.info("event=exit client=%s", session["client"])
        return "OK|Goodbye"
    else:
        return count_failure(session, "unknown_command", "ERROR|Unknown command")


def handle_client(conn, addr, users):
    client = addr[0] + ":" + str(addr[1])
    log.info("event=connect client=%s", client)

# idle timeout so a client that stops talking gets disconnected
    conn.settimeout(IDLE_TIMEOUT)
    session = {"state": CONNECTED, "user": None, "failures": 0,
               "closing": False, "client": client}

    try:
        while not session["closing"]:
            raw, too_long = read_message(conn)

            if raw is None:
                log.info("event=client_disconnected client=%s", client)
                break

            if too_long:
                reply = count_failure(session, "message_too_long", "ERROR|Message too long")
            else:
                reply = handle_message(session, users, raw)
            send_line(conn, reply)

    except socket.timeout:
        log.info("event=idle_timeout client=%s", client)
    except OSError:
        log.info("event=connection_error client=%s", client)
        # catch anything unexpected to protect from server crashes
    except Exception as err:
        log.error("event=internal_error client=%s type=%s", client, type(err).__name__)
    finally:
        conn.close()
        log.info("event=closed client=%s", client)


def serve():
    setup_logging()

    try:
        users = load_users()
    except AuthError as err:
        print(f"Cannot start: {err}. Run:  python setup_users.py <username>")
        return 1

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((HOST, PORT))
    except OSError as err:
        print(f"Cannot bind {HOST}:{PORT}: {err.strerror}")
        return 1
# one client at a time only 
    server_socket.listen(1)
    log.info("event=server_start host=%s port=%d", HOST, PORT)

    try:
        while True:
            conn, addr = server_socket.accept()
            handle_client(conn, addr, users)
    except KeyboardInterrupt:
        pass
    finally:
        server_socket.close()
        log.info("event=server_stop")
    return 0


if __name__ == "__main__":
    sys.exit(serve())