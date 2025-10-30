# ============================================================================
# QUANTUM-SAFE E-VOTING SYSTEM - KEY GENERATION
# ============================================================================
# File: generate_keys.py
# Purpose: Generate Kyber-512 and Dilithium-2 cryptographic keys
# Run: python generate_keys.py
# ============================================================================

import os
import crypto_utils as crypto

def main():
    """
    Generate all cryptographic keys required for the voting system.
    
    Keys generated:
    1. Kyber-512 keypair (quantum-safe encryption)
       - Public key: keys/kyber_public.key
       - Secret key: keys/kyber_secret.key
    
    2. Dilithium-2 keypair (quantum-safe signatures)
       - Public key: keys/dilithium_public.key
       - Secret key: keys/dilithium_secret.key
    """
    print("\n" + "="*70)
    print("QUANTUM-SAFE KEY GENERATION")
    print("="*70 + "\n")
    
    # Create keys directory if it doesn't exist
    os.makedirs('keys', exist_ok=True)
    print("✓ Keys directory ready\n")
    
    # Generate Kyber-512 keypair (for encryption)
    print("Step 1: Generating Kyber-512 keypair (quantum-safe encryption)...")
    print("-" * 70)
    try:
        kyber_public, kyber_secret = crypto.generate_kyber_keypair()
        
        # Save keys to files
        crypto.save_key_to_file(kyber_public, 'keys/kyber_public.key')
        crypto.save_key_to_file(kyber_secret, 'keys/kyber_secret.key')
        
        print("✓ Kyber-512 keys generated and saved\n")
    except Exception as e:
        print(f"✗ Error generating Kyber keys: {e}\n")
        return
    
    # Generate signature keypair (Dilithium2 or ML-DSA-44)
    print("Step 2: Generating quantum-safe signature keypair...")
    print("-" * 70)
    try:
        # Try to use Dilithium2, fall back to any available algorithm
        try:
            sig_public, sig_secret, sig_name = crypto.generate_signature_keypair("Dilithium2")
        except:
            sig_public, sig_secret, sig_name = crypto.generate_signature_keypair()
        
        # Save keys to files
        crypto.save_key_to_file(sig_public, 'keys/signature_public.key')
        crypto.save_key_to_file(sig_secret, 'keys/signature_secret.key')
        
        # Save algorithm name for later use
        with open('keys/signature_algorithm.txt', 'w') as f:
            f.write(sig_name)
        print(f"✓ Signature algorithm saved: {sig_name}")
        
        print(f"✓ Signature keys ({sig_name}) generated and saved\n")
    except Exception as e:
        print(f"✗ Error generating signature keys: {e}\n")
        return
    
    # Success message
    print("="*70)
    print("KEY GENERATION COMPLETE!")
    print("="*70)
    print("\nGenerated Files:")
    print("  ├── keys/kyber_public.key      (800 bytes)")
    print("  ├── keys/kyber_secret.key      (1632 bytes)")
    print("  ├── keys/signature_public.key  (varies by algorithm)")
    print("  ├── keys/signature_secret.key  (varies by algorithm)")
    print("  └── keys/signature_algorithm.txt (algorithm name)")
    print("\n⚠ SECURITY WARNING:")
    print("  - Keep secret keys (kyber_secret.key, signature_secret.key) SECURE!")
    print("  - Never commit secret keys to version control")
    print("  - Public keys can be shared safely")
    print("\nNext Steps:")
    print("  1. Run: python app.py")
    print("  2. Open browser to: http://127.0.0.1:5000")
    print("="*70 + "\n")

if __name__ == '__main__':
    main()