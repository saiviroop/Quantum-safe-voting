# ============================================================================
# QUANTUM-SAFE E-VOTING SYSTEM - DATABASE OPERATIONS
# ============================================================================
# File: database.py
# Purpose: All database operations for users, votes, candidates, and admins
# Database: SQLite (single file, no server required)
# ============================================================================

import sqlite3
import bcrypt
from datetime import datetime
import os

# Database file path
DATABASE_PATH = 'instance/voting.db'

# ============================================================================
# DATABASE CONNECTION
# ============================================================================

def get_db_connection():
    """
    Create and return a connection to the SQLite database.
    
    Returns:
        sqlite3.Connection: Database connection object
    
    Notes:
        - Creates 'instance' directory if it doesn't exist
        - Uses Row factory for dict-like access to rows
        - Enables foreign keys for referential integrity
    """
    # Create instance directory if needed
    os.makedirs('instance', exist_ok=True)
    
    # Connect to database
    conn = sqlite3.connect(DATABASE_PATH)
    
    # Enable dict-like access to rows (can use column names)
    conn.row_factory = sqlite3.Row
    
    # Enable foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON")
    
    return conn


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_database():
    
    """
    Initialize the database with all required tables.
    
    Tables created:
        - users: Regular voter accounts
        - admin_users: Admin accounts (separate from voters)
        - candidates: Election candidates
        - votes: Encrypted votes with signatures
        - voting_status: Controls whether voting is open/closed
    
    This function is idempotent (safe to run multiple times).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        print("Initializing database...")
        
        # Table 1: Regular Users (Voters)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                has_voted BOOLEAN DEFAULT 0,
                is_admin BOOLEAN DEFAULT 0,
                face_kyber_ciphertext BLOB,
                face_encrypted_data BLOB,
                face_nonce BLOB,
                face_registered BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✓ Table 'users' created (with face recognition fields)")
        
        # Table 2: Admin Users (Separate from voters)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✓ Table 'admin_users' created")
        
        # Table 3: Candidates
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS candidates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                party TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✓ Table 'candidates' created")
        
        # Table 4: Votes (Encrypted and Anonymous)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS votes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kyber_ciphertext BLOB NOT NULL,
                encrypted_data BLOB NOT NULL,
                nonce BLOB NOT NULL,
                signature BLOB NOT NULL,
                receipt_code TEXT UNIQUE NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✓ Table 'votes' created")
        
        # Table 5: Voting Status (Open/Closed)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS voting_status (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                is_open BOOLEAN DEFAULT 1,
                opened_at TIMESTAMP,
                closed_at TIMESTAMP
            )
        ''')
        print("✓ Table 'voting_status' created")
        
        # Initialize voting status if not exists
        cursor.execute('''
            INSERT OR IGNORE INTO voting_status (id, is_open, opened_at)
            VALUES (1, 1, ?)
        ''', (datetime.now(),))
        
        # Create default admin account (username: admin, password: admin123)
        create_default_admin(conn)
        
        conn.commit()
        print("\n✓ Database initialized successfully!")
        return True
    
    except sqlite3.Error as e:
        print(f"✗ Database initialization error: {e}")
        conn.rollback()
        return False
    
    finally:
        conn.close()


def create_default_admin(conn):
    """
    Create default admin account if it doesn't exist.
    
    Default credentials:
        Username: admin
        Password: admin123
    
    Args:
        conn: Database connection object
    """
    cursor = conn.cursor()
    
    # Check if admin already exists
    cursor.execute("SELECT * FROM admin_users WHERE username = ?", ('admin',))
    if cursor.fetchone():
        print("  ℹ Default admin already exists")
        return
    
    # Hash the default password
    password_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt(rounds=12))
    
    # Insert default admin
    cursor.execute('''
        INSERT INTO admin_users (username, password_hash)
        VALUES (?, ?)
    ''', ('admin', password_hash))
    
    print("  ✓ Default admin created (username: admin, password: admin123)")
    print("  ⚠ CHANGE THIS PASSWORD IN PRODUCTION!")


# ============================================================================
# USER OPERATIONS
# ============================================================================

def create_user(username, email, password):
    """
    Register a new user account.
    
    Args:
        username (str): Unique username
        email (str): Unique email address
        password (str): Plain text password (will be hashed)
    
    Returns:
        tuple: (success: bool, message: str)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Hash password with bcrypt (cost factor 12)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        
        # Insert user
        cursor.execute('''
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
        ''', (username, email, password_hash))
        
        conn.commit()
        print(f"✓ User '{username}' registered successfully")
        return True, "Registration successful!"
    
    except sqlite3.IntegrityError:
        # Username or email already exists
        return False, "Username or email already exists"
    
    except Exception as e:
        print(f"✗ Error creating user: {e}")
        return False, "Registration failed"
    
    finally:
        conn.close()


def verify_user_login(username, password):
    """
    Verify user credentials for login.
    
    Args:
        username (str): Username
        password (str): Plain text password
    
    Returns:
        tuple: (success: bool, user_data: dict or None)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Find user
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if not user:
            return False, None
        
        # Verify password
        if bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            # Convert Row object to dict
            user_data = {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'has_voted': bool(user['has_voted'])
            }
            return True, user_data
        else:
            return False, None
    
    except Exception as e:
        print(f"✗ Error verifying login: {e}")
        return False, None
    
    finally:
        conn.close()


def get_user_by_id(user_id):
    """
    Get user information by ID.
    
    Args:
        user_id (int): User ID
    
    Returns:
        dict or None: User data
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if user:
            return {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'has_voted': bool(user['has_voted'])
            }
        return None
    
    finally:
        conn.close()


def mark_user_voted(user_id):
    """
    Mark a user as having voted (prevent double voting).
    
    Args:
        user_id (int): User ID
    
    Returns:
        bool: Success status
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('UPDATE users SET has_voted = 1 WHERE id = ?', (user_id,))
        conn.commit()
        return True
    
    except Exception as e:
        print(f"✗ Error marking user as voted: {e}")
        return False
    
    finally:
        conn.close()


# ============================================================================
# ADMIN OPERATIONS
# ============================================================================

def verify_admin_login(username, password):
    """
    Verify admin credentials for login.
    
    Args:
        username (str): Admin username
        password (str): Plain text password
    
    Returns:
        tuple: (success: bool, admin_data: dict or None)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Find admin
        cursor.execute('SELECT * FROM admin_users WHERE username = ?', (username,))
        admin = cursor.fetchone()
        
        if not admin:
            return False, None
        
        # Verify password
        if bcrypt.checkpw(password.encode('utf-8'), admin['password_hash']):
            admin_data = {
                'id': admin['id'],
                'username': admin['username']
            }
            return True, admin_data
        else:
            return False, None
    
    except Exception as e:
        print(f"✗ Error verifying admin login: {e}")
        return False, None
    
    finally:
        conn.close()


# ============================================================================
# CANDIDATE OPERATIONS
# ============================================================================

def add_candidate(name, party, description=""):
    """
    Add a new candidate to the election.
    
    Args:
        name (str): Candidate name
        party (str): Political party
        description (str): Optional description
    
    Returns:
        tuple: (success: bool, message: str)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO candidates (name, party, description)
            VALUES (?, ?, ?)
        ''', (name, party, description))
        
        conn.commit()
        print(f"✓ Candidate '{name}' added")
        return True, "Candidate added successfully!"
    
    except Exception as e:
        print(f"✗ Error adding candidate: {e}")
        return False, "Failed to add candidate"
    
    finally:
        conn.close()


def get_all_candidates():
    """
    Get all candidates in the election.
    
    Returns:
        list: List of candidate dicts
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT * FROM candidates ORDER BY id')
        candidates = cursor.fetchall()
        
        return [dict(c) for c in candidates]
    
    finally:
        conn.close()


def delete_candidate(candidate_id):
    """
    Delete a candidate from the election.
    
    Args:
        candidate_id (int): Candidate ID
    
    Returns:
        bool: Success status
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('DELETE FROM candidates WHERE id = ?', (candidate_id,))
        conn.commit()
        print(f"✓ Candidate {candidate_id} deleted")
        return True
    
    except Exception as e:
        print(f"✗ Error deleting candidate: {e}")
        return False
    
    finally:
        conn.close()


# ============================================================================
# VOTE OPERATIONS
# ============================================================================

def save_vote(kyber_ciphertext, encrypted_data, nonce, signature, receipt_code):
    """
    Save an encrypted vote to the database.
    
    Args:
        kyber_ciphertext (bytes): Kyber KEM ciphertext
        encrypted_data (bytes): AES-GCM encrypted vote
        nonce (bytes): AES-GCM nonce
        signature (bytes): Dilithium signature
        receipt_code (str): Unique receipt code
    
    Returns:
        tuple: (success: bool, message: str)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO votes (kyber_ciphertext, encrypted_data, nonce, signature, receipt_code)
            VALUES (?, ?, ?, ?, ?)
        ''', (kyber_ciphertext, encrypted_data, nonce, signature, receipt_code))
        
        conn.commit()
        print(f"✓ Vote saved with receipt: {receipt_code}")
        return True, "Vote recorded successfully!"
    
    except sqlite3.IntegrityError:
        # Duplicate receipt code (extremely unlikely)
        return False, "Duplicate receipt code. Please try again."
    
    except Exception as e:
        print(f"✗ Error saving vote: {e}")
        return False, "Failed to save vote"
    
    finally:
        conn.close()


def get_vote_by_receipt(receipt_code):
    """
    Retrieve a vote by its receipt code.
    
    Args:
        receipt_code (str): Receipt code
    
    Returns:
        dict or None: Vote data
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT * FROM votes WHERE receipt_code = ?', (receipt_code,))
        vote = cursor.fetchone()
        
        if vote:
            return dict(vote)
        return None
    
    finally:
        conn.close()


def get_all_votes():
    """
    Get all votes from the database (for admin tallying).
    
    Returns:
        list: List of vote dicts with encrypted data
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT * FROM votes ORDER BY timestamp')
        votes = cursor.fetchall()
        
        return [dict(v) for v in votes]
    
    finally:
        conn.close()


def get_vote_count():
    """
    Get total number of votes cast.
    
    Returns:
        int: Vote count
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT COUNT(*) as count FROM votes')
        result = cursor.fetchone()
        return result['count']
    
    finally:
        conn.close()


# ============================================================================
# VOTING STATUS OPERATIONS
# ============================================================================

def is_voting_open():
    """
    Check if voting is currently open.
    
    Returns:
        bool: True if open, False if closed
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT is_open FROM voting_status WHERE id = 1')
        result = cursor.fetchone()
        
        return bool(result['is_open']) if result else True
    
    finally:
        conn.close()


def close_voting():
    """
    Close the voting (no more votes can be cast).
    
    Returns:
        bool: Success status
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE voting_status 
            SET is_open = 0, closed_at = ?
            WHERE id = 1
        ''', (datetime.now(),))
        
        conn.commit()
        print("✓ Voting closed")
        return True
    
    except Exception as e:
        print(f"✗ Error closing voting: {e}")
        return False
    
    finally:
        conn.close()


def open_voting():
    """
    Open/reopen the voting.
    
    Returns:
        bool: Success status
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE voting_status 
            SET is_open = 1, opened_at = ?
            WHERE id = 1
        ''', (datetime.now(),))
        
        conn.commit()
        print("✓ Voting opened")
        return True
    
    except Exception as e:
        print(f"✗ Error opening voting: {e}")
        return False
    
    finally:
        conn.close()


# ============================================================================
# STATISTICS
# ============================================================================

def get_statistics():
    """
    Get voting statistics for admin dashboard.
    
    Returns:
        dict: Statistics including total users, votes, candidates, etc.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        stats = {}
        
        # Total registered users
        cursor.execute('SELECT COUNT(*) as count FROM users')
        stats['total_users'] = cursor.fetchone()['count']
        
        # Total votes cast
        cursor.execute('SELECT COUNT(*) as count FROM votes')
        stats['total_votes'] = cursor.fetchone()['count']
        
        # Total candidates
        cursor.execute('SELECT COUNT(*) as count FROM candidates')
        stats['total_candidates'] = cursor.fetchone()['count']
        
        # Users who voted
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE has_voted = 1')
        stats['users_voted'] = cursor.fetchone()['count']
        
        # Participation rate
        if stats['total_users'] > 0:
            stats['participation_rate'] = (stats['users_voted'] / stats['total_users']) * 100
        else:
            stats['participation_rate'] = 0
        
        # Voting status
        stats['is_voting_open'] = is_voting_open()
        
        return stats
    
    finally:
        conn.close()

# ============================================================================
# FACE RECOGNITION OPERATIONS
# ============================================================================

def save_user_face_data(user_id, kyber_ciphertext, encrypted_data, nonce):
    """
    Save encrypted face encoding data for a user.
    
    This function stores the face data encrypted with Kyber-512 for quantum safety.
    
    Args:
        user_id (int): User ID
        kyber_ciphertext (bytes): Kyber-512 ciphertext (encapsulated key)
        encrypted_data (bytes): AES-GCM encrypted face encoding
        nonce (bytes): AES-GCM nonce for decryption
    
    Returns:
        tuple: (success: bool, message: str)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE users
            SET face_kyber_ciphertext = ?,
                face_encrypted_data = ?,
                face_nonce = ?,
                face_registered = 1
            WHERE id = ?
        ''', (kyber_ciphertext, encrypted_data, nonce, user_id))
        
        conn.commit()
        
        if cursor.rowcount > 0:
            print(f"✓ Face data saved for user {user_id}")
            return True, "Face data saved successfully!"
        else:
            print(f"✗ User {user_id} not found")
            return False, "User not found"
    
    except Exception as e:
        print(f"✗ Error saving face data: {e}")
        return False, f"Failed to save face data: {str(e)}"
    
    finally:
        conn.close()


def get_user_face_data(user_id):
    """
    Retrieve encrypted face encoding data for a user.
    
    This returns the encrypted face data that needs to be decrypted
    using Kyber-512 and AES-GCM before face comparison.
    
    Args:
        user_id (int): User ID
    
    Returns:
        dict or None: Face data including kyber_ciphertext, encrypted_data, 
                     nonce, face_registered. Returns None if no face data.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT face_kyber_ciphertext, face_encrypted_data, 
                   face_nonce, face_registered
            FROM users
            WHERE id = ?
        ''', (user_id,))
        
        result = cursor.fetchone()
        
        if result and result['face_registered']:
            return {
                'kyber_ciphertext': result['face_kyber_ciphertext'],
                'encrypted_data': result['face_encrypted_data'],
                'nonce': result['face_nonce'],
                'face_registered': True
            }
        return None
    
    except Exception as e:
        print(f"✗ Error getting face data: {e}")
        return None
    
    finally:
        conn.close()


def has_face_registered(user_id):
    """
    Check if a user has registered their face.
    
    Args:
        user_id (int): User ID
    
    Returns:
        bool: True if face is registered, False otherwise
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT face_registered
            FROM users
            WHERE id = ?
        ''', (user_id,))
        
        result = cursor.fetchone()
        return bool(result['face_registered']) if result else False
    
    except Exception as e:
        print(f"✗ Error checking face registration: {e}")
        return False
    
    finally:
        conn.close()


def delete_user_face_data(user_id):
    """
    Delete face data for a user (opt-out of face recognition).
    
    Args:
        user_id (int): User ID
    
    Returns:
        tuple: (success: bool, message: str)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE users
            SET face_kyber_ciphertext = NULL,
                face_encrypted_data = NULL,
                face_nonce = NULL,
                face_registered = 0
            WHERE id = ?
        ''', (user_id,))
        
        conn.commit()
        
        if cursor.rowcount > 0:
            print(f"✓ Face data deleted for user {user_id}")
            return True, "Face data removed successfully!"
        else:
            return False, "User not found"
    
    except Exception as e:
        print(f"✗ Error deleting face data: {e}")
        return False, f"Failed to delete face data: {str(e)}"
    
    finally:
        conn.close()


# ============================================================================
# END OF DATABASE OPERATIONS
# ============================================================================