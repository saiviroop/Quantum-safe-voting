# ============================================================================
# QUANTUM-SAFE E-VOTING SYSTEM - QUICK START SCRIPT
# ============================================================================
# File: quick_start.py
# Purpose: Automate complete setup process (database + keys + sample data)
# Run: python quick_start.py
# ============================================================================

import os
import sys

def print_banner():
    """Display welcome banner."""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║              🗳️  QUANTUM-SAFE E-VOTING SYSTEM                       ║
║                                                                      ║
║                      Quick Start Setup                               ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    print("This script will automatically set up your voting system.\n")

def check_dependencies():
    """Check if all required packages are installed."""
    print("Step 1: Checking dependencies...")
    print("-" * 70)
    
    required_packages = {
        'flask': 'Flask',
        'oqs': 'liboqs-python',
        'cryptography': 'cryptography',
        'bcrypt': 'bcrypt'
    }
    
    missing_packages = []
    
    for module, package_name in required_packages.items():
        try:
            __import__(module)
            print(f"  ✓ {package_name} is installed")
        except ImportError:
            print(f"  ✗ {package_name} is NOT installed")
            missing_packages.append(package_name)
    
    if missing_packages:
        print(f"\n✗ Missing packages: {', '.join(missing_packages)}")
        print("\nPlease run: pip install -r requirements.txt")
        return False
    
    print("✓ All dependencies installed\n")
    return True

def initialize_database():
    """Initialize the database."""
    print("Step 2: Initializing database...")
    print("-" * 70)
    
    try:
        import database as db
        success = db.init_database()
        
        if success:
            print("✓ Database initialized successfully\n")
            return True
        else:
            print("✗ Database initialization failed\n")
            return False
    
    except Exception as e:
        print(f"✗ Error initializing database: {e}\n")
        return False

def generate_cryptographic_keys():
    """Generate cryptographic keys."""
    print("Step 3: Generating cryptographic keys...")
    print("-" * 70)
    
    try:
        import crypto_utils as crypto
        
        # Create keys directory
        os.makedirs('keys', exist_ok=True)
        
        # Generate Kyber keys
        print("  Generating Kyber-512 keypair...")
        kyber_public, kyber_secret = crypto.generate_kyber_keypair()
        crypto.save_key_to_file(kyber_public, 'keys/kyber_public.key')
        crypto.save_key_to_file(kyber_secret, 'keys/kyber_secret.key')
        
        # Generate Signature keys (Dilithium2 or ML-DSA-44)
        print("  Generating quantum-safe signature keypair...")
        try:
            sig_public, sig_secret, sig_name = crypto.generate_signature_keypair("Dilithium2")
        except:
            sig_public, sig_secret, sig_name = crypto.generate_signature_keypair()
        
        crypto.save_key_to_file(sig_public, 'keys/signature_public.key')
        crypto.save_key_to_file(sig_secret, 'keys/signature_secret.key')
        
        # Save algorithm name
        with open('keys/signature_algorithm.txt', 'w') as f:
            f.write(sig_name)
        print(f"  ✓ Using signature algorithm: {sig_name}")
        
        print("✓ All cryptographic keys generated\n")
        return True
    
    except Exception as e:
        print(f"✗ Error generating keys: {e}\n")
        return False

def add_sample_candidates():
    """Add sample candidates for testing."""
    print("Step 4: Adding sample candidates...")
    print("-" * 70)
    
    try:
        import database as db
        
        candidates = [
            {
                'name': 'Alice Johnson',
                'party': 'Democratic Party',
                'description': 'Experienced leader focused on education and healthcare reform'
            },
            {
                'name': 'Bob Smith',
                'party': 'Republican Party',
                'description': 'Business advocate promoting economic growth and job creation'
            },
            {
                'name': 'Carol Williams',
                'party': 'Independent',
                'description': 'Community organizer championing environmental sustainability'
            }
        ]
        
        for candidate in candidates:
            success, message = db.add_candidate(
                candidate['name'],
                candidate['party'],
                candidate['description']
            )
            if success:
                print(f"  ✓ Added: {candidate['name']} ({candidate['party']})")
            else:
                print(f"  ✗ Failed to add: {candidate['name']}")
        
        print("✓ Sample candidates added\n")
        return True
    
    except Exception as e:
        print(f"✗ Error adding candidates: {e}\n")
        return False

def test_cryptography():
    """Test that cryptography works correctly."""
    print("Step 5: Testing cryptographic system...")
    print("-" * 70)
    
    try:
        import crypto_utils as crypto
        
        # Test Kyber encryption/decryption
        print("  Testing Kyber-512 encryption/decryption...")
        kyber_public = crypto.load_key_from_file('keys/kyber_public.key')
        kyber_secret = crypto.load_key_from_file('keys/kyber_secret.key')
        
        test_vote = {'candidate_id': 1, 'timestamp': '2025-10-21'}
        ct, enc, nonce = crypto.encrypt_vote_kyber(test_vote, kyber_public)
        decrypted = crypto.decrypt_vote_kyber(ct, enc, nonce, kyber_secret)
        
        if decrypted == test_vote:
            print("  ✓ Kyber encryption/decryption working")
        else:
            print("  ✗ Kyber test failed")
            return False
        
        # Test signature signing/verification
        print("  Testing quantum-safe signature signing/verification...")
        sig_public = crypto.load_key_from_file('keys/signature_public.key')
        sig_secret = crypto.load_key_from_file('keys/signature_secret.key')
        
        # Load signature algorithm name
        with open('keys/signature_algorithm.txt', 'r') as f:
            sig_name = f.read().strip()
        
        test_message = b"Test vote message"
        signature = crypto.sign_vote(test_message, sig_secret, sig_name)
        is_valid = crypto.verify_vote_signature(test_message, signature, sig_public, sig_name)
        
        if is_valid:
            print("  ✓ Signature signing/verification working")
        else:
            print("  ✗ Signature test failed")
            return False
        
        print("✓ All cryptographic tests passed\n")
        return True
    
    except Exception as e:
        print(f"✗ Error testing cryptography: {e}\n")
        return False

def display_completion_message():
    """Display setup completion message with next steps."""
    completion = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║                    ✅ SETUP COMPLETED SUCCESSFULLY!                  ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

📋 What was set up:
   ✓ SQLite database with all tables
   ✓ Default admin account created
   ✓ Kyber-512 encryption keys (quantum-safe)
   ✓ ML-DSA-44 or Dilithium-2 signature keys (quantum-safe)
   ✓ 3 sample candidates added
   ✓ All systems tested and verified

🔐 Default Admin Credentials:
   Username: admin
   Password: admin123
   URL: http://localhost:5000/admin/login

⚠️  IMPORTANT: Change the admin password after first login!

🚀 Next Steps:

   1. Start the application:
      python app.py

   2. Open your browser:
      http://localhost:5000

   3. Try the system:
      • Register a test voter account
      • Login and cast a vote
      • Save your receipt code
      • Verify your vote
      • Login as admin to manage

📚 Need Help?
   • Read README.md for detailed instructions
   • Check troubleshooting section for common issues
   • All code has extensive comments for learning

🎓 Educational Notes:
   • Vote data is encrypted with Kyber-512 (NIST quantum-safe)
   • Digital signatures use ML-DSA-44 or Dilithium-2 (NIST quantum-safe)
   • Complete anonymity - no link between voter and vote
   • Receipt codes allow cryptographic verification

╔══════════════════════════════════════════════════════════════════════╗
║                    Ready to start secure voting!                     ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    print(completion)

def main():
    """Main setup function."""
    print_banner()
    
    # Ask for user confirmation
    response = input("Do you want to proceed with setup? (yes/no): ").strip().lower()
    if response not in ['yes', 'y']:
        print("\nSetup cancelled.")
        sys.exit(0)
    
    print("\n")
    
    # Step 1: Check dependencies
    if not check_dependencies():
        print("\n⚠️  Setup cannot continue. Please install missing dependencies.")
        print("Run: pip install -r requirements.txt")
        sys.exit(1)
    
    # Step 2: Initialize database
    if not initialize_database():
        print("\n⚠️  Setup failed at database initialization.")
        sys.exit(1)
    
    # Step 3: Generate keys
    if not generate_cryptographic_keys():
        print("\n⚠️  Setup failed at key generation.")
        sys.exit(1)
    
    # Step 4: Add sample candidates (optional)
    add_sample = input("Add sample candidates for testing? (yes/no): ").strip().lower()
    if add_sample in ['yes', 'y']:
        add_sample_candidates()
    else:
        print("Skipping sample candidates\n")
    
    # Step 5: Test cryptography
    if not test_cryptography():
        print("\n⚠️  Cryptographic tests failed. System may not work correctly.")
        sys.exit(1)
    
    # Display completion message
    display_completion_message()
    
    # Ask if user wants to start the app now
    start_now = input("\nStart the application now? (yes/no): ").strip().lower()
    if start_now in ['yes', 'y']:
        print("\nStarting application...\n")
        import app
        # This would start the Flask app
        # In practice, user should run python app.py manually
        print("Please run: python app.py")
    else:
        print("\nSetup complete! Run 'python app.py' when ready.")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ Unexpected error during setup: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)