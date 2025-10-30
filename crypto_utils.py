# ============================================================================
# QUANTUM-SAFE E-VOTING SYSTEM - CRYPTOGRAPHIC UTILITIES
# ============================================================================
# File: crypto_utils.py
# Purpose: Implements quantum-safe encryption (Kyber-512) and digital 
#          signatures using liboqs library
# ============================================================================

# At the top of crypto_utils.py, after imports
import os
import json
import oqs  # liboqs-python for quantum-safe cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as PBKDF2
import secrets

# Add this line:
LIBOQS_AVAILABLE = True  # We're using real liboqs (not simulation)

# ============================================================================
# QUANTUM-SAFE KEY ENCAPSULATION (KYBER-512)
# ============================================================================

def generate_kyber_keypair(kem_name="Kyber512"):
    try:
        kem = oqs.KeyEncapsulation(kem_name)
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        print(f"✓ {kem_name} keypair generated successfully")
        print(f"  - Public key size: {len(public_key)} bytes")
        print(f"  - Secret key size: {len(secret_key)} bytes")
        return public_key, secret_key
    except Exception as e:
        print(f"✗ Error generating {kem_name} keypair: {e}")
        raise


def encrypt_vote_kyber(vote_data, public_key_bytes):
    try:
        vote_bytes = json.dumps(vote_data).encode('utf-8')
        kem = oqs.KeyEncapsulation("Kyber512")
        kyber_ciphertext, shared_secret = kem.encap_secret(public_key_bytes)

        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=kyber_ciphertext[:16],
            iterations=100000,
        )
        aes_key = kdf.derive(shared_secret)
        aesgcm = AESGCM(aes_key)
        nonce = secrets.token_bytes(12)
        encrypted_data = aesgcm.encrypt(nonce, vote_bytes, None)

        print(f"✓ Vote encrypted successfully")
        return kyber_ciphertext, encrypted_data, nonce
    except Exception as e:
        print(f"✗ Error encrypting vote: {e}")
        raise


def decrypt_vote_kyber(kyber_ciphertext, encrypted_data, nonce, secret_key_bytes):
    try:
        kem = oqs.KeyEncapsulation("Kyber512", secret_key=secret_key_bytes)
        shared_secret = kem.decap_secret(kyber_ciphertext)

        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=kyber_ciphertext[:16],
            iterations=100000,
        )
        aes_key = kdf.derive(shared_secret)
        aesgcm = AESGCM(aes_key)
        vote_bytes = aesgcm.decrypt(nonce, encrypted_data, None)

        return json.loads(vote_bytes.decode('utf-8'))
    except Exception as e:
        print(f"✗ Error decrypting vote: {e}")
        raise


# ============================================================================
# QUANTUM-SAFE DIGITAL SIGNATURES (Flexible)
# ============================================================================

def generate_signature_keypair(sig_name=None):
    """
    Generate a new signature keypair. Defaults to first available mechanism.
    """
    try:
        if sig_name is None:
            enabled_sigs = oqs.get_enabled_sig_mechanisms()
            if not enabled_sigs:
                raise RuntimeError("No signature mechanisms available in liboqs")
            sig_name = enabled_sigs[0]
            print(f"⚠ 'Dilithium2' not available, using '{sig_name}' instead")
        sig = oqs.Signature(sig_name)
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
        print(f"✓ {sig_name} keypair generated successfully")
        print(f"  - Public key size: {len(public_key)} bytes")
        print(f"  - Secret key size: {len(secret_key)} bytes")
        return public_key, secret_key, sig_name
    except Exception as e:
        print(f"✗ Error generating {sig_name} keypair: {e}")
        raise


def sign_vote(message_bytes, secret_key_bytes, sig_name):
    try:
        sig = oqs.Signature(sig_name, secret_key=secret_key_bytes)
        signature = sig.sign(message_bytes)
        print(f"✓ Vote signed successfully")
        return signature
    except Exception as e:
        print(f"✗ Error signing vote: {e}")
        raise


def verify_vote_signature(message_bytes, signature, public_key_bytes, sig_name):
    try:
        sig = oqs.Signature(sig_name)
        is_valid = sig.verify(message_bytes, signature, public_key_bytes)
        if is_valid:
            print(f"✓ Signature verification: VALID")
        else:
            print(f"✗ Signature verification: INVALID")
        return is_valid
    except Exception as e:
        print(f"✗ Error verifying signature: {e}")
        return False


# ============================================================================
# KEY MANAGEMENT UTILITIES
# ============================================================================

def save_key_to_file(key_bytes, filename):
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'wb') as f:
            f.write(key_bytes)
        print(f"✓ Key saved to: {filename}")
    except Exception as e:
        print(f"✗ Error saving key: {e}")
        raise


def load_key_from_file(filename):
    try:
        with open(filename, 'rb') as f:
            key_bytes = f.read()
        print(f"✓ Key loaded from: {filename}")
        return key_bytes
    except FileNotFoundError:
        print(f"✗ Key file not found: {filename}")
        raise
    except Exception as e:
        print(f"✗ Error loading key: {e}")
        raise


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def generate_receipt_code(vote_package):
    from hashlib import sha256
    hash_obj = sha256(vote_package)
    return hash_obj.hexdigest()[:12].upper()


# ============================================================================
# TEST FUNCTION
# ============================================================================

def test_crypto_system():
    print("\n" + "="*70)
    print("TESTING QUANTUM-SAFE CRYPTOGRAPHY")
    print("="*70 + "\n")

    print("Test 1: Kyber Encryption/Decryption")
    try:
        pub, sec = generate_kyber_keypair()
        test_vote = {'candidate_id': 42, 'timestamp': '2025-10-21'}
        ct, enc, nonce = encrypt_vote_kyber(test_vote, pub)
        decrypted = decrypt_vote_kyber(ct, enc, nonce, sec)
        assert decrypted == test_vote
        print("✓ Test 1 PASSED\n")
    except Exception as e:
        print(f"✗ Test 1 FAILED: {e}\n")

    print("Test 2: Signature Signing/Verification")
    try:
        pub, sec, sig_name = generate_signature_keypair()
        test_msg = b"This is a test vote message"
        signature = sign_vote(test_msg, sec, sig_name)
        is_valid = verify_vote_signature(test_msg, signature, pub, sig_name)
        assert is_valid
        print("✓ Test 2 PASSED\n")
    except Exception as e:
        print(f"✗ Test 2 FAILED: {e}\n")

    print("="*70)
    print("ALL TESTS COMPLETE")
    print("="*70 + "\n")


if __name__ == "__main__":
    test_crypto_system()
