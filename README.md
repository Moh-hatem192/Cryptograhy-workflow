# Cryptograhy-workflow
This project implements a complete cryptographic workflow using Python, combining multiple core concepts in modern cryptography, including:

RSA Key Generation

SHA-256 Hashing

Digital Signatures

Diffie-Hellman Key Exchange

AES Encryption (CTR Mode)

Replay Attack Protection (Freshness Mechanism)

The system is designed as an interactive menu-driven application, allowing users to test each cryptographic component step by step.

📌 Features
1️⃣ RSA Key Generation

Generates a 2048-bit RSA key pair

Public key: (e, n)

Private key: (d, n)

Keys are securely stored in:

public_key.txt

private_key.txt

2️⃣ SHA-256 Hashing

Computes the SHA-256 hash of any user-input message

Ensures data integrity

Output is displayed in HEX format

3️⃣ Digital Signature (RSA + SHA-256)

Simulates:

Alex (sender) signing a message

Bob (receiver) verifying it

Process:

Hash message using SHA-256

Sign hash using RSA private key

Verify using RSA public key

✅ Detects message tampering
❌ Rejects modified messages

4️⃣ Diffie-Hellman Key Exchange

Generates shared secret between two parties:

Alice (Doctor)

Bob (Patient)

Uses:

2048-bit parameters

Secure key exchange mechanism

Shared key is stored in:

session_key.txt

5️⃣ AES-CTR Encryption with Freshness Protection

Uses shared key from Diffie-Hellman

Derives AES-256 key using SHA-256

Encrypts medical message using AES in CTR mode

🔒 Security Features:

Timestamp validation

Rejects messages outside a 30-second window

Message nonce

Prevents replay attacks

Replay detection

Duplicate messages are rejected

6️⃣ RSA Short Message Encryption

Simulates secure communication:

Bob encrypts message

Alex decrypts message

Uses RSA encryption:

Encryption: C = M^e mod n

Decryption: M = C^d mod n

▶️ How to Run
1. Install dependencies
pip install pycryptodome cryptography
2. Run the script
python your_script_name.py

📂 Files Generated
File	Description
public_key.txt	RSA public key
private_key.txt	RSA private key
session_key.txt	Shared key from Diffie-Hellman

Notes

This project is for educational purposes only

RSA is used without padding → not secure in real-world systems

AES-CTR requires nonce uniqueness for security

Replay protection is implemented using:

Timestamp

Message nonce
