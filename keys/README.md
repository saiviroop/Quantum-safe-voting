# 🔐 Cryptographic Keys Directory

This directory contains the quantum-safe cryptographic keys used by the voting system.

## 📁 Key Files

After running `python generate_keys.py`, you will have 4 key files:

### Encryption Keys (Kyber-512)
1. **kyber_public.key** (800 bytes)
   - Used to encrypt votes
   - Safe to share publicly
   - Required for vote casting

2. **kyber_secret.key** (1632 bytes) ⚠️
   - Used to decrypt votes
   - **MUST BE KEPT SECRET**
   - Only admin needs this for tallying
   - Never commit to version control

### Signature Keys (Dilithium-2)
3. **dilithium_public.key** (1312 bytes)
   - Used to verify vote signatures
   - Safe to share publicly
   - Required for vote verification

4. **dilithium_secret.key** (2528 bytes) ⚠️
   - Used to sign votes
   - **MUST BE KEPT SECRET**
   - Required for vote casting
   - Never commit to version control

## 🚨 Security Warnings

### Critical Rules

1. **NEVER commit secret keys to Git**
   - The `.gitignore` file prevents this
   - Double-check before pushing to remote repositories

2. **Backup secret keys securely**
   - Store in encrypted storage
   - Keep multiple copies in secure locations
   - If lost, all votes become unrecoverable!

3. **Restrict file permissions** (Linux/macOS)
   ```bash
   chmod 600 keys/*_secret.key  # Owner read/write only
   chmod 644 keys/*_public.key  # Public readable
   ```

4. **In production:**
   - Use Hardware Security Modules (HSM)
   - Implement key rotation policies
   - Use multi-party computation for decryption
   - Maintain audit logs of key access

## 📝 Key Generation

To generate new keys:

```bash
python generate_keys.py
```

This will:
1. Create new Kyber-512 keypair
2. Create new Dilithium-2 keypair
3. Save all 4 keys to this directory
4. **WARNING**: Overwrites existing keys!

## 🔄 Key Rotation

For production systems, implement key rotation:

1. **Before voting starts:**
   - Generate new keys
   - Test encryption/decryption
   - Backup old keys

2. **During voting:**
   - NEVER rotate keys!
   - Keep consistent keys throughout election

3. **After voting ends:**
   - Keep keys until results verified
   - Archive keys securely
   - Generate new keys for next election

## 🛡️ Key Security Checklist

- [ ] Secret keys have restrictive permissions
- [ ] Secret keys are NOT in version control
- [ ] Multiple backups exist in secure locations
- [ ] Access to keys is logged and monitored
- [ ] Keys are encrypted at rest (production)
- [ ] Key access requires authentication
- [ ] Backup restoration has been tested

## 📊 Key Sizes

| Key Type | Algorithm | Size (bytes) | Purpose |
|----------|-----------|--------------|---------|
| Public Encryption | Kyber-512 | 800 | Encrypt votes |
| Secret Decryption | Kyber-512 | 1632 | Decrypt votes |
| Public Verification | Dilithium-2 | 1312 | Verify signatures |
| Secret Signing | Dilithium-2 | 2528 | Sign votes |

## 🔬 Algorithm Details

### Kyber-512
- **Type**: Key Encapsulation Mechanism (KEM)
- **Security**: NIST Security Level 1 (~AES-128)
- **Quantum Safe**: Yes (lattice-based)
- **Standard**: NIST Post-Quantum Cryptography

### Dilithium-2
- **Type**: Digital Signature Scheme
- **Security**: NIST Security Level 2 (~SHA-256)
- **Quantum Safe**: Yes (lattice-based)
- **Standard**: NIST Post-Quantum Cryptography

## 🧪 Testing Keys

To verify keys work correctly:

```bash
python crypto_utils.py
```

This runs automated tests on:
- Kyber encryption/decryption
- Dilithium signing/verification

## 💾 Backup Procedures

### Development
```bash
# Backup keys
cp keys/*_secret.key backups/
```

### Production
1. Use encrypted backup storage
2. Store in multiple physical locations
3. Use key management systems
4. Implement disaster recovery procedures

## 🚫 What NOT to Do

❌ Never email keys  
❌ Never store in cloud without encryption  
❌ Never hardcode keys in source code  
❌ Never share secret keys  
❌ Never use same keys for different elections  
❌ Never commit to public repositories  

## ✅ What TO Do

✅ Use hardware security modules (HSM) in production  
✅ Implement access controls  
✅ Maintain audit logs  
✅ Regular security audits  
✅ Test key recovery procedures  
✅ Document key lifecycle  

## 📞 Key Compromise

If secret keys are compromised:

1. **Immediate Actions:**
   - Revoke compromised keys
   - Generate new keys
   - Notify all stakeholders
   - Audit all votes

2. **Investigation:**
   - Determine scope of breach
   - Review access logs
   - Identify attack vector

3. **Recovery:**
   - Re-encrypt all votes with new keys
   - Update all systems
   - Implement additional security measures

## 📚 Additional Resources

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Open Quantum Safe](https://openquantumsafe.org/)
- [Kyber Specification](https://pq-crystals.org/kyber/)
- [Dilithium Specification](https://pq-crystals.org/dilithium/)

---

**Remember**: The security of the entire voting system depends on keeping these secret keys secure! 🔒