# FSCT 8561 Midterm
# Setup

Requires Python 3.10 or newer.

python -m venv .venv
.venv\Scripts\activate          
pip install -r requirements.txt
python setup_users.py nicholas

`setup_users.py` asks for a password and creates the user.

# Run

Open three terminals and run one command in each, in this order:

python test_website.py
python server.py
python client.py

Log in with the username, password, and 6-digit OTP. To get the OTP, run
`python show_otp.py nicholas` in a fourth terminal.

# Testing

1. Log in, then choose 1 (PCAP analysis)
2. Try a wrong password, a wrong OTP, and a username that does not exist
3. Fail the login three times in a row (the connection is locked)
4. Choose 2 (port scan) with the test website running, then stop it and scan again
5. Choose 2 with bad input: `0`, `70000`, `abc`, or a start port higher than the end port
6. Choose 3 (HTTP check) with the test website running, then stop it and check again
7. Stop the server while the client is logged in

To send a request without logging in:

python -c "import socket;s=socket.create_connection(('127.0.0.1',8700));s.sendall(b'PCAP|\n');print(s.recv(1024))"
