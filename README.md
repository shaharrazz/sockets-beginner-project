# 🔒 Multi-Threaded Secure TLS/SSL Cyber Server (C Implementation)

A high-performance, secure, and multi-threaded TCP server built in **C** using **POSIX Threads (`pthread`)** and **OpenSSL**. 

This project demonstrates core cybersecurity and networking concepts, including TLS encryption (TLS 1.2 minimum, TLS 1.3 negotiated by modern OpenSSL), salted SHA-256 password hashing, rate limiting against Denial of Service (DoS) attacks, brute-force lockout protection, and thread-safe concurrent connection handling.

---

## ✨ Features

- **End-to-End Encryption (TLS/SSL):** Secured communication channel using OpenSSL (`SSL_read`, `SSL_write`), preventing eavesdropping and Man-in-the-Middle (MitM) attacks.
- **Multi-Threaded Architecture:** Handles multiple concurrent client connections asynchronously using `pthread_create` and `pthread_detach`.
- **Salted SHA-256 Password Hashing:** Cryptographically secure authentication mechanism using OpenSSL's `EVP` API with custom dynamic salting.
- **Per-IP Brute-Force Lockout:** Blocks logins from a source IP for **30 seconds** after **3 failed attempts**, so one attacker cannot lock out other users.
- **Per-Session Rate Limiting (basic DoS mitigation):** Restricts each connection to a maximum of **5 requests per second**. Exceeding the threshold triggers an HTTP `429 Too Many Requests` warning and drops the socket.
- **Thread-Safe Security Event Logging:** Timestamped events with the client's source IP:port, written to console and `server.log`, protected by `pthread_mutex_t`.

---

## 🏗️ Architecture & Security Design
+------------------+         Encrypted TLS Channel         +----------------------+
|  OpenSSL Client  | <===================================> | Multi-Thread Server  |
|  (s_client)      |        (SSL_read / SSL_write)         | (OpenSSL + pthreads) |
+------------------+                                       +----------------------+
|
+-----------+-----------+
|                       |
[ Mutex Lock ]          [ Mutex Lock ]
|                       |
Rate Limit Check       Account Lockout &
& Logging System        Salted Hash Auth

---

## 🛠️ Prerequisites

Ensure you have the required compilers and OpenSSL libraries installed on your Linux machine (Ubuntu/Debian/WSL):

sudo apt update
sudo apt install build-essential libssl-dev openssl -y

Getting Started
1. Clone the Repository

git clone https://github.com/shaharrazz/sockets-beginner-project.git
cd sockets-beginner-project

2. Generate Self-Signed SSL Certificates
Generate a private key (server.key) and a self-signed certificate (server.crt):

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key \
  -out server.crt \
  -subj "/C=IL/ST=Center/L=BneiBrak/O=ITQ/OU=CyberSec/CN=127.0.0.1"

3. Compile the Server
Compile the code with threading (-lpthread) and OpenSSL (-lcrypto -lssl) libraries:
gcc -Wall server_multi.c -o server_multi -lpthread -lssl -lcrypto

4. Run the Server
   
./server_multi

Connecting with OpenSSL Client
Open a separate terminal window and connect to the secure server using openssl s_client:

openssl s_client -connect 127.0.0.1:8080 -crlf -quiet

Command,Usage,Description,Authentication Required
LOGIN,LOGIN <username> <password>,Authenticates the user via Salted SHA-256 hash matching.,❌ No
PING,PING,Health check command; responds with PONG!.,✅ Yes
TIME,TIME,Returns server session status/time info.,✅ Yes
EXIT,EXIT,Safely closes the TLS connection.,❌ No

## Files

- `server_multi.c` – the main project: multi-threaded TLS server with authentication, lockout, rate limiting and security logging.
- `server.c` / `client.c` – the first stage of the project: a basic single-client plaintext TCP server and client.

## Security Event Log Sample (`server.log`)

All connection and security events are logged thread-safely with the client's source IP:port:

```
[2026-11-20 09:26:40] [INFO] [Thread 139962387265216] Secure TLS client 127.0.0.1:32768 connected on sock 4. Active clients: 1
[2026-11-20 09:26:40] [WARNING] SECURITY WARNING: Failed login attempt (1/3) for user 'shahar' from 127.0.0.1:32768
[2026-11-20 09:26:40] [WARNING] SECURITY WARNING: Failed login attempt (2/3) for user 'shahar' from 127.0.0.1:32768
[2026-11-20 09:26:41] [WARNING] SECURITY ALERT: 3 failed login attempts from 127.0.0.1:32768 (last user 'shahar'). Source LOCKED for 30 seconds
[2026-11-20 09:26:41] [WARNING] SECURITY ALERT: Rejected login from 127.0.0.1:32768 - source is LOCKED
[2026-11-20 09:27:28] [WARNING] SECURITY ALERT: Client 127.0.0.1:39572 exceeded rate limit (6 requests/sec). Connection dropped.
```
