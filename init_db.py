# ============================================================================
# QUANTUM-SAFE E-VOTING SYSTEM - DATABASE INITIALIZATION
# ============================================================================
# File: init_db.py
# Purpose: Initialize the SQLite database with all required tables
# Run: python init_db.py
# ============================================================================

import database as db

def main():
    """
    Initialize the database and create default admin account.
    """
    print("\n" + "="*70)
    print("DATABASE INITIALIZATION")
    print("="*70 + "\n")
    
    # Initialize database
    success = db.init_database()
    
    if success:
        print("\n" + "="*70)
        print("DATABASE READY!")
        print("="*70)
        print("\nDefault Admin Account:")
        print("  Username: admin")
        print("  Password: admin123")
        print("\n⚠ IMPORTANT: Change this password after first login!")
        print("\nNext Steps:")
        print("  1. Run: python generate_keys.py")
        print("  2. Run: python app.py")
        print("="*70 + "\n")
    else:
        print("\n✗ Database initialization failed!")
        print("  Check error messages above.\n")

if __name__ == '__main__':
    main()# File: 10_init_db.py
# Database Initialization Script
# Creates all database tables and sets up default admin account

import sqlite3
import bcrypt
from datetime import datetime
import os

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================

DATABASE_NAME = 'voting.db'
DEFAULT_ADMIN_USERNAME = 'admin'
DEFAULT_ADMIN_PASSWORD = 'admin123'
DEFAULT_ADMIN_EMAIL = 'admin@quantumvote.com'

# =============================================================================
# DATABASE SCHEMA
# =============================================================================

SCHEMA = {
    'users': '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            is_admin BOOLEAN DEFAULT 0,
            has_voted BOOLEAN DEFAULT 0,
            face_encoding BLOB,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            voted_at TIMESTAMP,
            last_login TIMESTAMP
        )
    ''',
    
    'candidates': '''
        CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            party TEXT NOT NULL,
            bio TEXT,
            image_url TEXT,
            manifesto TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''',
    
    'votes': '''
        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            candidate_id INTEGER NOT NULL,
            encrypted_vote BLOB NOT NULL,
            signature BLOB NOT NULL,
            receipt_code TEXT UNIQUE NOT NULL,
            voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            decrypted_vote TEXT,
            is_verified BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (candidate_id) REFERENCES candidates(id)
        )
    ''',
    
    'audit_log': '''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''',
    
    'elections': '''
        CREATE TABLE IF NOT EXISTS elections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            start_date TIMESTAMP NOT NULL,
            end_date TIMESTAMP NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''',
    
    'sessions': '''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    '''
}

# =============================================================================
# DATABASE INITIALIZATION FUNCTIONS
# =============================================================================

def create_database():
    """Create database file and all tables"""
    print("🔨 Creating database...")
    
    # Check if database already exists
    if os.path.exists(DATABASE_NAME):
        response = input(f"⚠️  Database '{DATABASE_NAME}' already exists. Recreate? (yes/no): ")
        if response.lower() != 'yes':
            print("❌ Database creation cancelled")
            return False
        
        # Backup existing database
        backup_name = f"{DATABASE_NAME}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.rename(DATABASE_NAME, backup_name)
        print(f"✓ Backed up existing database to {backup_name}")
    
    # Create database connection
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Create all tables
    for table_name, schema in SCHEMA.items():
        try:
            cursor.execute(schema)
            print(f"✓ Created table: {table_name}")
        except sqlite3.Error as e:
            print(f"❌ Error creating table {table_name}: {e}")
            return False
    
    conn.commit()
    conn.close()
    
    print("✅ Database created successfully!")
    return True

def create_admin_account():
    """Create default admin account"""
    print("\n👤 Creating admin account...")
    
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Check if admin already exists
    cursor.execute("SELECT id FROM users WHERE username = ?", (DEFAULT_ADMIN_USERNAME,))
    if cursor.fetchone():
        print(f"⚠️  Admin account '{DEFAULT_ADMIN_USERNAME}' already exists")
        conn.close()
        return True
    
    # Hash the password
    password_hash = bcrypt.hashpw(DEFAULT_ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt())
    
    # Insert admin user
    try:
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, full_name, is_admin, registered_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            DEFAULT_ADMIN_USERNAME,
            DEFAULT_ADMIN_EMAIL,
            password_hash,
            'System Administrator',
            1,
            datetime.now()
        ))
        
        conn.commit()
        admin_id = cursor.lastrowid
        
        # Log the admin creation
        cursor.execute('''
            INSERT INTO audit_log (user_id, action, details)
            VALUES (?, ?, ?)
        ''', (admin_id, 'ADMIN_CREATED', 'Initial admin account created'))
        
        conn.commit()
        
        print(f"✓ Admin account created successfully")
        print(f"  Username: {DEFAULT_ADMIN_USERNAME}")
        print(f"  Password: {DEFAULT_ADMIN_PASSWORD}")
        print(f"  Email: {DEFAULT_ADMIN_EMAIL}")
        print("\n⚠️  IMPORTANT: Change the admin password after first login!")
        
    except sqlite3.Error as e:
        print(f"❌ Error creating admin account: {e}")
        return False
    finally:
        conn.close()
    
    return True

def create_sample_candidates():
    """Create some sample candidates for testing"""
    print("\n🎯 Creating sample candidates...")
    
    response = input("Do you want to add sample candidates? (yes/no): ")
    if response.lower() != 'yes':
        print("⏭️  Skipped sample candidates")
        return True
    
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Get admin ID
    cursor.execute("SELECT id FROM users WHERE is_admin = 1 LIMIT 1")
    admin = cursor.fetchone()
    if not admin:
        print("❌ No admin account found. Cannot create candidates.")
        conn.close()
        return False
    
    admin_id = admin[0]
    
    # Sample candidates
    sample_candidates = [
        {
            'name': 'Alice Johnson',
            'party': 'Progressive Party',
            'bio': 'Former mayor with 15 years of public service experience.',
            'manifesto': 'Focus on education, healthcare, and environmental sustainability.'
        },
        {
            'name': 'Bob Williams',
            'party': 'Conservative Alliance',
            'bio': 'Successful entrepreneur and economic advisor.',
            'manifesto': 'Economic growth, tax reform, and job creation.'
        },
        {
            'name': 'Carol Martinez',
            'party': 'Independent',
            'bio': 'Community organizer and social justice advocate.',
            'manifesto': 'Social equality, affordable housing, and criminal justice reform.'
        },
        {
            'name': 'David Chen',
            'party': 'Green Future',
            'bio': 'Environmental scientist and climate change expert.',
            'manifesto': 'Climate action, renewable energy, and sustainable development.'
        }
    ]
    
    # Insert candidates
    for candidate in sample_candidates:
        try:
            cursor.execute('''
                INSERT INTO candidates (name, party, bio, manifesto, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                candidate['name'],
                candidate['party'],
                candidate['bio'],
                candidate['manifesto'],
                admin_id
            ))
            print(f"✓ Added candidate: {candidate['name']} ({candidate['party']})")
        except sqlite3.Error as e:
            print(f"❌ Error adding candidate {candidate['name']}: {e}")
    
    conn.commit()
    conn.close()
    
    print("✅ Sample candidates created successfully!")
    return True

def create_default_election():
    """Create a default election"""
    print("\n🗳️  Creating default election...")
    
    response = input("Do you want to create a default election? (yes/no): ")
    if response.lower() != 'yes':
        print("⏭️  Skipped default election")
        return True
    
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Get admin ID
    cursor.execute("SELECT id FROM users WHERE is_admin = 1 LIMIT 1")
    admin = cursor.fetchone()
    if not admin:
        print("❌ No admin account found. Cannot create election.")
        conn.close()
        return False
    
    admin_id = admin[0]
    
    # Create election with dates
    from datetime import datetime, timedelta
    
    start_date = datetime.now()
    end_date = start_date + timedelta(days=7)  # Election lasts 7 days
    
    try:
        cursor.execute('''
            INSERT INTO elections (title, description, start_date, end_date, is_active, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            'General Election 2024',
            'Vote for your preferred candidate in this general election.',
            start_date,
            end_date,
            1,
            admin_id
        ))
        
        conn.commit()
        
        print(f"✓ Election created successfully")
        print(f"  Title: General Election 2024")
        print(f"  Start: {start_date.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  End: {end_date.strftime('%Y-%m-%d %H:%M:%S')}")
        
    except sqlite3.Error as e:
        print(f"❌ Error creating election: {e}")
        return False
    finally:
        conn.close()
    
    return True

def verify_database():
    """Verify that the database was created correctly"""
    print("\n🔍 Verifying database...")
    
    if not os.path.exists(DATABASE_NAME):
        print(f"❌ Database file '{DATABASE_NAME}' not found")
        return False
    
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Check all tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    missing_tables = []
    for table_name in SCHEMA.keys():
        if table_name not in tables:
            missing_tables.append(table_name)
    
    if missing_tables:
        print(f"❌ Missing tables: {', '.join(missing_tables)}")
        conn.close()
        return False
    
    print(f"✓ All {len(SCHEMA)} tables exist")
    
    # Check admin exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
    admin_count = cursor.fetchone()[0]
    print(f"✓ Found {admin_count} admin user(s)")
    
    # Check candidates
    cursor.execute("SELECT COUNT(*) FROM candidates")
    candidate_count = cursor.fetchone()[0]
    print(f"✓ Found {candidate_count} candidate(s)")
    
    # Check elections
    cursor.execute("SELECT COUNT(*) FROM elections")
    election_count = cursor.fetchone()[0]
    print(f"✓ Found {election_count} election(s)")
    
    # Show database size
    db_size = os.path.getsize(DATABASE_NAME)
    print(f"✓ Database size: {db_size:,} bytes ({db_size/1024:.2f} KB)")
    
    conn.close()
    
    print("✅ Database verification passed!")
    return True

def show_database_info():
    """Display database information"""
    print("\n" + "="*70)
    print("DATABASE INFORMATION")
    print("="*70)
    
    if not os.path.exists(DATABASE_NAME):
        print(f"❌ Database '{DATABASE_NAME}' not found")
        return
    
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Get table counts
    print("\n📊 Table Statistics:")
    print("-" * 70)
    
    for table_name in SCHEMA.keys():
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        count = cursor.fetchone()[0]
        print(f"  {table_name:20} {count:>10} records")
    
    # Get admin info
    print("\n👥 Admin Accounts:")
    print("-" * 70)
    cursor.execute('''
        SELECT username, email, registered_at 
        FROM users 
        WHERE is_admin = 1
    ''')
    
    for row in cursor.fetchall():
        print(f"  Username: {row[0]}")
        print(f"  Email: {row[1]}")
        print(f"  Registered: {row[2]}")
        print()
    
    # Get candidates
    if cursor.execute("SELECT COUNT(*) FROM candidates").fetchone()[0] > 0:
        print("🎯 Candidates:")
        print("-" * 70)
        cursor.execute("SELECT name, party FROM candidates")
        
        for idx, row in enumerate(cursor.fetchall(), 1):
            print(f"  {idx}. {row[0]} ({row[1]})")
    
    # Get active elections
    if cursor.execute("SELECT COUNT(*) FROM elections WHERE is_active = 1").fetchone()[0] > 0:
        print("\n🗳️  Active Elections:")
        print("-" * 70)
        cursor.execute('''
            SELECT title, start_date, end_date 
            FROM elections 
            WHERE is_active = 1
        ''')
        
        for row in cursor.fetchall():
            print(f"  {row[0]}")
            print(f"  Start: {row[1]}")
            print(f"  End: {row[2]}")
            print()
    
    conn.close()
    
    print("="*70 + "\n")

# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    """Main initialization function"""
    print("\n" + "="*70)
    print("QUANTUM-SAFE E-VOTING SYSTEM")
    print("Database Initialization Script")
    print("="*70 + "\n")
    
    # Step 1: Create database and tables
    if not create_database():
        print("\n❌ Database initialization failed!")
        return False
    
    # Step 2: Create admin account
    if not create_admin_account():
        print("\n❌ Admin account creation failed!")
        return False
    
    # Step 3: Create sample candidates (optional)
    create_sample_candidates()
    
    # Step 4: Create default election (optional)
    create_default_election()
    
    # Step 5: Verify database
    if not verify_database():
        print("\n❌ Database verification failed!")
        return False
    
    # Step 6: Show database info
    show_database_info()
    
    print("\n" + "="*70)
    print("✅ DATABASE INITIALIZATION COMPLETE!")
    print("="*70)
    print("\n📝 Next Steps:")
    print("  1. Run: python generate_keys.py (to generate quantum-safe keys)")
    print("  2. Run: python app.py (to start the voting application)")
    print(f"  3. Login as admin: username='{DEFAULT_ADMIN_USERNAME}', password='{DEFAULT_ADMIN_PASSWORD}'")
    print("  4. IMPORTANT: Change admin password after first login!")
    print("\n" + "="*70 + "\n")
    
    return True

def reset_database():
    """Reset database (delete and recreate)"""
    print("\n⚠️  DATABASE RESET")
    print("="*70)
    print("This will DELETE ALL DATA and recreate the database!")
    print("="*70 + "\n")
    
    response = input("Are you ABSOLUTELY sure? Type 'RESET' to confirm: ")
    if response != 'RESET':
        print("❌ Reset cancelled")
        return False
    
    # Delete database
    if os.path.exists(DATABASE_NAME):
        os.remove(DATABASE_NAME)
        print(f"✓ Deleted {DATABASE_NAME}")
    
    # Recreate
    return main()

# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    import sys
    
    # Check for reset flag
    if len(sys.argv) > 1 and sys.argv[1] == '--reset':
        reset_database()
    else:
        main()
