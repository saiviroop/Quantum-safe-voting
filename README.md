# 🗳️ Quantum-Safe E-Voting System

A secure, anonymous, and verifiable electronic voting system powered by **post-quantum cryptography** (Kyber-512 and Dilithium-2).

## 🔐 Features

- **Quantum-Safe Encryption**: Uses Kyber-512 (NIST-approved post-quantum algorithm)
- **Digital Signatures**: Dilithium-2 signatures prevent vote tampering
- **Complete Anonymity**: Zero link between voter identity and vote content
- **Verifiable Votes**: Cryptographic receipts allow voters to verify their votes
- **One Vote Per User**: System enforces single-vote policy
- **Admin Dashboard**: Manage candidates, control voting, and tally results

## 📋 Prerequisites

Before installation, ensure you have:

- **Python 3.11 or higher** ([Download](https://www.python.org/downloads/))
- **pip** (Python package installer - included with Python)
- **Modern web browser** (Chrome, Firefox, Edge, Safari)
- **Internet connection** (for initial package download)

## 🚀 Installation

### Step 1: Download the Project

Extract the `quantum-voting` folder to your desired location.

### Step 2: Open Terminal/Command Prompt

**Windows:**
- Press `Win + R`, type `cmd`, press Enter
- Navigate to project folder: `cd path\to\quantum-voting`

**macOS/Linux:**
- Open Terminal
- Navigate to project folder: `cd path/to/quantum-voting`

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

**Expected output:**
```
Successfully installed Flask-3.0.0 liboqs-python-0.10.1 cryptography-41.0.7 bcrypt-4.1.2 ...
```

**Troubleshooting:**
- If you see "command not found": Try `python -m pip install -r requirements.txt`
- If you see "externally-managed-environment" (Linux): Use a virtual environment (see below)

### Step 4: Initialize Database

```bash
python init_db.py
```

**Expected output:**
```
✓ Table 'users' created
✓ Table 'admin_users' created
✓ Table 'candidates' created
✓ Table 'votes' created
✓ Table 'voting_status' created
✓ Default admin created (username: admin, password: admin123)
```

### Step 5: Generate Cryptographic Keys

```bash
python generate_keys.py
```

**Expected output:**
```
✓ Kyber-512 keypair generated successfully
✓ Dilithium-2 keypair generated successfully
```

This creates 4 key files in the `keys/` directory.

### Step 6: Start the Application

```bash
python app.py
```

**Expected output:**
```
✓ liboqs-python installed
✓ cryptography library installed
✓ bcrypt installed
✓ Database found
✓ Cryptographic keys found

SYSTEM READY
Starting server at: http://127.0.0.1:5000
```

### Step 7: Open in Browser

Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

or

```
http://localhost:5000
```

## 👤 Default Credentials

### Admin Account
- **Username**: `admin`
- **Password**: `admin123`
- **URL**: `http://localhost:5000/admin/login`

⚠️ **IMPORTANT**: Change the default admin password in production!

## 📖 Usage Guide

### For Voters

1. **Register an Account**
   - Click "Register" in the navigation bar
   - Fill in username, email, and password
   - Accept terms and submit

2. **Login**
   - Click "Login"
   - Enter your credentials

3. **Cast Your Vote**
   - Click "Vote" in the navigation bar
   - Select your preferred candidate
   - Confirm your selection
   - Click "Encrypt & Submit Vote"

4. **Save Your Receipt**
   - You'll receive a 12-character receipt code
   - **SAVE THIS CODE** - you cannot retrieve it later!
   - Example: `A1B2C3D4E5F6`

5. **Verify Your Vote**
   - Click "Verify Vote" in the navigation bar
   - Enter your receipt code
   - System will confirm your vote was recorded correctly

### For Administrators

1. **Login as Admin**
   - Go to `http://localhost:5000/admin/login`
   - Use admin credentials

2. **Add Candidates**
   - Enter candidate name, party, and optional description
   - Click "Add"

3. **Manage Voting**
   - **Open Voting**: Allow users to cast votes
   - **Close Voting**: Stop accepting new votes

4. **Tally Results**
   - Click "Decrypt & Tally Votes"
   - System decrypts all votes using Kyber secret key
   - View results with vote counts and percentages

5. **Remove Candidates**
   - Click "Delete" next to any candidate (before votes are cast)

## 🏗️ Project Structure

```
quantum-voting/
│
├── app.py                    # Main Flask application (all routes)
├── crypto_utils.py           # Kyber + Dilithium cryptography functions
├── database.py               # All database operations
├── models.py                 # Data models and validation
├── init_db.py                # Database initialization script
├── generate_keys.py          # Key generation script
├── requirements.txt          # Python dependencies
├── README.md                 # This file
│
├── keys/                     # Cryptographic keys (⚠️ keep secret!)
│   ├── kyber_public.key     # Encryption public key
│   ├── kyber_secret.key     # Encryption secret key (SECRET!)
│   ├── dilithium_public.key # Signature public key
│   └── dilithium_secret.key # Signature secret key (SECRET!)
│
├── templates/                # HTML templates
│   ├── base.html            # Base template with navbar
│   ├── index.html           # Home page
│   ├── register.html        # User registration
│   ├── login.html           # User login
│   ├── vote.html            # Voting interface
│   ├── receipt.html         # Vote receipt
│   ├── verify.html          # Vote verification
│   ├── admin_login.html     # Admin login
│   └── admin_dashboard.html # Admin panel
│
├── static/                   # Static files
│   ├── css/
│   │   └── style.css        # Custom styles
│   └── js/
│       └── main.js          # JavaScript functionality
│
└── instance/                 # Instance folder (auto-created)
    └── voting.db            # SQLite database
```

## 🔒 Security Features

### Encryption (Kyber-512)
- **Algorithm**: Kyber-512 (NIST PQC standard)
- **Purpose**: Encrypt vote data before storage
- **Security**: Resistant to quantum computer attacks
- **Key Size**: 800 bytes (public), 1632 bytes (secret)

### Digital Signatures (Dilithium-2)
- **Algorithm**: Dilithium-2 (NIST PQC standard)
- **Purpose**: Sign votes to prevent tampering
- **Security**: Quantum-resistant digital signatures
- **Key Size**: 1312 bytes (public), 2528 bytes (secret)

### Password Hashing (bcrypt)
- **Algorithm**: bcrypt with cost factor 12
- **Purpose**: Securely hash user passwords
- **Security**: Slow hashing prevents brute-force attacks

### Anonymity
- **No Voter IDs**: Vote records contain no user identification
- **Random Tokens**: Additional randomness for unlinkability
- **Separation**: User table separate from vote table

## 🛠️ Troubleshooting

### Issue: "Command 'python' not found"
**Solution**: Try `python3` instead of `python`

### Issue: "Port 5000 already in use"
**Solution**: 
1. Stop other programs using port 5000, or
2. Edit `app.py` line 650: Change `port=5000` to `port=5001`

### Issue: "Keys not found"
**Solution**: Run `python generate_keys.py`

### Issue: "Database not found"
**Solution**: Run `python init_db.py`

### Issue: "pip install fails on Windows"
**Solution**:
1. Upgrade pip: `python -m pip install --upgrade pip`
2. Retry installation

### Issue: "externally-managed-environment" (Linux/macOS)
**Solution**: Use a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Issue: "ModuleNotFoundError: No module named 'flask'"
**Solution**: Dependencies not installed. Run `pip install -r requirements.txt`

## 🧪 Testing

### Test Cryptography
```bash
python crypto_utils.py
```
This runs built-in tests for Kyber and Dilithium.

### Manual Testing Flow
1. Register 3 test users
2. Login as each user and vote for different candidates
3. Verify each vote using receipt codes
4. Login as admin and tally results
5. Confirm vote counts are correct

## 📊 Database Schema

### Users Table
- `id`: Primary key
- `username`: Unique username
- `email`: Unique email
- `password_hash`: bcrypt hash
- `has_voted`: Boolean flag
- `created_at`: Registration timestamp

### Votes Table
- `id`: Primary key
- `kyber_ciphertext`: Kyber KEM ciphertext
- `encrypted_data`: AES-GCM encrypted vote
- `nonce`: AES-GCM nonce
- `signature`: Dilithium-2 signature
- `receipt_code`: Unique verification code
- `timestamp`: Vote timestamp

### Candidates Table
- `id`: Primary key
- `name`: Candidate name
- `party`: Political party
- `description`: Optional bio
- `created_at`: Added timestamp

## 🚨 Important Notes

### Security Warnings

⚠️ **Default Admin Password**: Change `admin/admin123` immediately in production

⚠️ **Secret Keys**: Never commit `keys/*_secret.key` files to version control

⚠️ **HTTPS**: Use HTTPS in production (not HTTP)

⚠️ **Debug Mode**: Set `debug=False` in `app.py` for production

### Production Deployment

For production use:
1. Change admin password
2. Use environment variables for secrets
3. Deploy with proper WSGI server (gunicorn, waitress)
4. Enable HTTPS with SSL certificate
5. Use PostgreSQL instead of SQLite
6. Implement rate limiting
7. Add audit logging
8. Regular security audits

## 📝 License

This is an educational project. Feel free to use and modify.

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Multi-factor authentication
- Email verification
- Vote export formats (PDF, Excel)
- Real-time results updates
- Mobile app
- Accessibility improvements

## 📞 Support

For issues or questions:
1. Check the Troubleshooting section
2. Review error messages carefully
3. Ensure all installation steps were followed
4. Check Python version (must be 3.11+)

## 🎓 Educational Use

This system demonstrates:
- Post-quantum cryptography implementation
- Secure web application development
- Anonymous voting systems
- Flask framework usage
- Database design
- Cryptographic protocols

## ✅ System Requirements

- **OS**: Windows 11, macOS, Linux
- **Python**: 3.11 or higher
- **RAM**: 2GB minimum
- **Disk**: 100MB free space
- **Browser**: Any modern browser

## 📈 Version

**Version**: 1.0.0  
**Release Date**: 2025  
**Cryptography**: Kyber-512, Dilithium-2 (NIST PQC)

---

**Built with**: Flask, liboqs-python, Bootstrap 5

**Cryptography Standards**: NIST Post-Quantum Cryptography

**Ready for**: Educational demos, research, prototyping

---

🗳️ **Secure Voting for a Quantum Future** 🔐