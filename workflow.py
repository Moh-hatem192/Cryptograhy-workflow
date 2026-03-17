# =========================
# Cryptography Assignment Workflow Menu
# (Functions + while True menu)
# =========================

def rsa_key_generation():
    from Crypto.Util.number import getPrime, GCD

    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while GCD(e, phi) != 1:
        e = getPrime(16)

    d = pow(e, -1, phi)

    with open("public_key.txt", "w") as pub_file:
        pub_file.write(f"e = {e}\n")
        pub_file.write(f"n = {n}\n")

    with open("private_key.txt", "w") as priv_file:
        priv_file.write(f"d = {d}\n")
        priv_file.write(f"n = {n}\n")
        

    print("\n--- Public Key (from file) ---")
    print(open("public_key.txt").read())

    print("--- Private Key (from file) ---")
    print(open("private_key.txt").read().splitlines()[0])


def digital_signature_sha256_rsa():
    import hashlib

    # =========================================================
    # B2: RSA Digital Signature on SHA-256 (Alex signs, Bob verifies)
    # - Message is fixed (no input)
    # - Keys are read from files (generated earlier)
    # - Bob computes his own hash and compares it with the hash recovered from signature
    # =========================================================

    # 1) Fixed medical message
    message = "Patient: Ali Ahmad | Diagnosis: Seasonal Flu | Prescription: Paracetamol 500mg twice daily"

    print("=== B2: Digital Signature using RSA on SHA-256 ===\n")
    print("[Message]")
    print(message)

    # ---------------------------------------------------------
    # 2) Read keys from files (exact style you asked for)
    # ---------------------------------------------------------

    print("\n[Reading keys from files...]")

    # Read entire public key file (e and n)
    public_key_text = open("public_key.txt").read()

    # Read only first line of private key file (d only, do NOT print n)
    private_key_text = open("private_key.txt").read().splitlines()[0]

    # Extract e and n from public key
    pub_lines = public_key_text.splitlines()
    e = int(pub_lines[0].split("=", 1)[1].strip())     # public exponent
    n = int(pub_lines[1].split("=", 1)[1].strip())     # modulus

    # Extract d from private key
    d = int(private_key_text.split("=", 1)[1].strip()) # private exponent

    print("✅ Keys loaded successfully.")
    print(f"Public key:  e = {e}")
    print("Private key: d is loaded (hidden for security)")

    # ---------------------------------------------------------
    # 3) Alex hashes the message and signs it
    # ---------------------------------------------------------

    print("\n--- Alex Signing ---")

    # Alex computes SHA-256 hash (hex)
    alex_hash_hex = hashlib.sha256(message.encode("utf-8")).hexdigest().upper()
    print("Alex SHA-256 hash (HEX):", alex_hash_hex)

    # Convert hash to integer and reduce mod n (needed for RSA math)
    alex_hash_int = int(alex_hash_hex, 16) % n
    print("Alex hash as integer (mod n):", alex_hash_int)

    # Alex signs: Signature = hash^d mod n
    signature = pow(alex_hash_int, d, n)
    print("Alex signature (int):", signature)
    print("Alex signature (HEX):", hex(signature)[2:].upper())

    # ---------------------------------------------------------
    # 4) Bob verifies: compute hash, then “unsign” signature
    # ---------------------------------------------------------
    message = "Patient: Ali Ahmad | Diagnosis: Seasonal Flu | Prescription: Paracetamol 500mg twice daily"
    # edited message
    #message = "Patient: Ali Ahmad | Biagnosis: Seasonal Flu | Prescription: Paracetamol 500mg twice daily"

    print("\n--- Bob Verifying ---")

    # Bob computes SHA-256 hash of received message
    bob_hash_hex = hashlib.sha256(message.encode("utf-8")).hexdigest().upper()
    print("Bob SHA-256 hash (HEX):", bob_hash_hex)

    bob_hash_int = int(bob_hash_hex, 16) % n
    print("Bob hash as integer (mod n):", bob_hash_int)

    # Bob “unsigns” (verifies) using public key:
    # recovered_hash = signature^e mod n
    recovered_hash = pow(signature, e, n)
    print("Bob recovered hash from signature (int):", recovered_hash)

    # ---------------------------------------------------------
    # 5) Compare
    # ---------------------------------------------------------

    print("\n--- Comparison ---")
    if recovered_hash == bob_hash_int:
        print("✅ VERIFIED: Bob's hash matches the recovered hash.")
        print("✅ Conclusion: The message is authentic and unchanged (integrity + authenticity).")
    else:
        print("❌ FAILED: Bob's hash does NOT match the recovered hash.")
        print("❌ Conclusion: The message is changed")
        print('Message is rejected')


def diffie_hellman_key_generate():
    from cryptography.hazmat.primitives.asymmetric import dh

    # Generate public DH parameters (p, g)
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    # Alice generate public parameters
    params_numbers = parameters.parameter_numbers()
    p = params_numbers.p
    g = params_numbers.g

    print('Alice sending public parameters to bob...')

    # Alice (Doctor) key pair
    alice_private = parameters.generate_private_key()
    alice_public = alice_private.public_key()

    # Bob (Patient) key pair
    bob_private = parameters.generate_private_key()
    bob_public = bob_private.public_key()

    print("Public keys being exchanged:")

    # Extract public values (y)
    alice_public_y = alice_public.public_numbers().y
    bob_public_y = bob_public.public_numbers().y

    # Shared secret derivation
    alice_shared = alice_private.exchange(bob_public).hex()
    bob_shared = bob_private.exchange(alice_public).hex()



    print("Public DH Parameters:")
    print("p (prime):", p)
    print("g (generator):", g)
    print("-" * 60)


    print("Alice public key (y):", alice_public_y)
    print("Bob public key (y):", bob_public_y)
    print("-" * 60)
    # Confirm both sides derived the same key
    print("Checking if secret key match?")
    result = alice_shared == bob_shared

    with open("session_key.txt", "w") as f:
        f.write(alice_shared)

    if result:
        print('Secret key match')
        print(f"Alice shared key: {alice_shared}")
        print(f"Bob shared key: {bob_shared}")


def diffie_hellman_aes_ctr_freshness():
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    import hashlib
    import time


    DH_HEX_FILE = "session_key.txt"
    TIME_WINDOW = 30                      

    # Same medical message from Part A
    medical_message = "Patient: Ali Ahmad | Diagnosis: Seasonal Flu | Prescription: Paracetamol 500mg twice daily"



    dh_hex = open(DH_HEX_FILE, "r", encoding="utf-8").read().strip()
    dh_shared_secret = bytes.fromhex(dh_hex)
    # the shared key generated from the Deffi-hellman size is too large
    aes_key = hashlib.sha256(dh_shared_secret).digest()   # 32 bytes = 256-bit AES key

    print("AES-CTR encryption")
    print("AES session key (HEX):", aes_key.hex())
    print("-" * 60)


    timestamp = int(time.time())
    message_nonce = get_random_bytes(8)  # used for replay protection (unique per message)
    aes_nonce = get_random_bytes(8)      # AES-CTR nonce (new random each encryption)

    payload = f"{timestamp}|{message_nonce.hex()}|{medical_message}"
    payload_bytes = payload.encode("utf-8")

    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=aes_nonce)
    ciphertext = cipher.encrypt(payload_bytes)

    print("--- Sender ---")
    print("AES Nonce (HEX):", aes_nonce.hex())
    print("Message Nonce (HEX):", message_nonce.hex())
    print("Ciphertext (HEX):", ciphertext.hex())
    print("-" * 60)

    # This is the transmitted packet
    packet = {"nonce": aes_nonce, "ciphertext": ciphertext}

    # =========================
    # 3) Receiver: freshness checks + decryption
    #    - reject timestamps outside time window
    #    - reject repeated message nonce (replay)
    # =========================
    seen_message_nonces = set()

    def receive(pkt, label):
        print(f"--- Receiver: {label} ---")

        # Decrypt ciphertext
        cipher_dec = AES.new(aes_key, AES.MODE_CTR, nonce=pkt["nonce"])
        decrypted_text = cipher_dec.decrypt(pkt["ciphertext"]).decode("utf-8")
        print("Decrypted payload:", decrypted_text)

        # Parse fields (format is guaranteed valid)
        ts_str, msgnonce_hex, data = decrypted_text.split("|", 2)
        ts = int(ts_str)

        # Timestamp freshness check
        now = int(time.time())
        if abs(now - ts) > TIME_WINDOW:
            print("❌ Rejected: timestamp outside acceptable window")
            print("-" * 60)
            return

        # Replay protection check
        if msgnonce_hex in seen_message_nonces:
            print("❌ Rejected: replay detected (message nonce repeated)")
            print("-" * 60)
            return

        # Accept message
        seen_message_nonces.add(msgnonce_hex)
        print("✅ Accepted: freshness checks passed")
        print("Recovered plaintext:", data)
        print("-" * 60)


    # 4) Valid first reception
    receive(packet, "First attempt (valid)")

    # 5) Replay the same packet (same nonce + same ciphertext) -> must be rejected

    receive(packet, "Replay attempt (should be rejected)")


def rsa_short_message_encrypt_decrypt():
    message = input('Enter a short message: ')
    # -----------------------------
    # Read Alex's public key (e, n)
    # -----------------------------
    public_key_text = open("public_key.txt").read()
    pub_lines = public_key_text.splitlines()

    e = int(pub_lines[0].split("=", 1)[1].strip())
    n = int(pub_lines[1].split("=", 1)[1].strip())

    # -----------------------------
    # Read Alex's private key (d)
    # -----------------------------
    private_key_text = open("private_key.txt").read().splitlines()[0]
    d = int(private_key_text.split("=", 1)[1].strip())

    print("[Alex] Private key loaded securely")

    # -----------------------------
    # Bob encrypts the short message
    # -----------------------------

    # Convert message to integer
    message_bytes = message.encode("utf-8")
    message_int = int.from_bytes(message_bytes, byteorder="big")

    # RSA encryption: C = M^e mod n
    cipher_int = pow(message_int, e, n)

    # Convert ciphertext integer to HEX
    cipher_hex = hex(cipher_int)[2:].upper()


    # -----------------------------
    # Alex decrypts the ciphertext
    # -----------------------------

    # Convert HEX back to integer
    received_cipher_int = int(cipher_hex, 16)

    # RSA decryption: M = C^d mod n
    decrypted_int = pow(received_cipher_int, d, n)

    # Convert decrypted integer back to text
    decrypted_bytes = decrypted_int.to_bytes(
        (decrypted_int.bit_length() + 7) // 8, byteorder="big"
    )

    decrypted_message = decrypted_bytes.decode("utf-8")

    print("=== B3: RSA Short Message Encryption ===\n")
    print("Plaintext message:", message)
    print("\n[Bob] Read Alex's public key")
    print("\n--- Bob Encrypting ---")
    print("Ciphertext (HEX):", cipher_hex)
    print("\n--- Alex Decrypting ---")
    print("\nVerification:",
          "✅ Success" if decrypted_message == message else "❌ Failed")
    print("Recovered plaintext:", decrypted_message)
    # -----------------------------
    # Verification
    # -----------------------------

def sha256_hashing():
    import hashlib
    # -------------------------------
    # 1) User input (plaintext message)
    # -------------------------------
    message = input("Enter the medical message: ")

    # -------------------------------
    # 2) Apply SHA-256
    # -------------------------------
    hash_hex = hashlib.sha256(message.encode("utf-8")).hexdigest()

    print("\n--- SHA-256 HASH ---")
    print("Hash (HEX):", hash_hex.upper())

# =========================
# MENU (workflow)
# =========================
# =========================
# MENU (workflow)
# =========================
while True:
    print("\n" + "=" * 60)
    print("CRYPTOGRAPHY ASSIGNMENT WORKFLOW MENU")
    print("=" * 60)
    print("1) RSA Key Generation (2048-bit) -> writes public_key.txt & private_key.txt")
    print("2) SHA-256 Hashing (Integrity)")
    print("3) B2 Digital Signature (SHA-256 + RSA) [Alex signs / Bob verifies]")
    print("4) C1 Diffie-Hellman Key Generation -> writes session_key.txt")
    print("5) C2 DH-derived AES-CTR + Freshness + Replay Rejection")
    print("6) B3 RSA Short Message Encrypt/Decrypt (Bob -> Alex)")
    print("0) Exit")

    choice = input("Choose an option: ").strip()

    if choice == "1":
        rsa_key_generation()
    elif choice == "2":
        sha256_hashing()
    elif choice == "3":
        digital_signature_sha256_rsa()
    elif choice == "4":
        diffie_hellman_key_generate()
    elif choice == "5":
        diffie_hellman_aes_ctr_freshness()
    elif choice == "6":
        rsa_short_message_encrypt_decrypt()
    elif choice == "0":
        print("Goodbye!")
        break
    else:
        print("❌ Invalid choice. Try again.")
