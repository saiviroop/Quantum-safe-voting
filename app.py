# ============================================================================
# QUANTUM-SAFE E-VOTING SYSTEM - MAIN APPLICATION
# ============================================================================
# File: app.py
# Purpose: Flask web application with all routes for voting system
# Run: python app.py
# URL: http://127.0.0.1:5000
# ============================================================================

import os
import sys
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import json

# Import our custom modules
import database as db
from database import DATABASE_PATH
import crypto_utils as crypto
from models import validate_username, validate_email, validate_password, validate_candidate_data
import face_utils as face  # Import face recognition utilities

# ============================================================================
# CHECK DEPENDENCIES
# ============================================================================

try:
    import oqs
    LIBOQS_AVAILABLE = True
    print("✓ liboqs-python installed (quantum-safe mode)")
except (ImportError, RuntimeError) as e:
    LIBOQS_AVAILABLE = False
    print("⚠ liboqs-python NOT available - using SIMULATION mode")
    print(f"  Error: {e}")
    print("  System will work but NOT be quantum-safe (educational only)")
    print()

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    print("✓ cryptography library installed")
except ImportError:
    print("✗ ERROR: cryptography not installed!")
    print("  Run: pip install cryptography==41.0.7")
    sys.exit(1)

try:
    import bcrypt
    print("✓ bcrypt installed")
except ImportError:
    print("✗ ERROR: bcrypt not installed!")
    print("  Run: pip install bcrypt==4.1.2")
    sys.exit(1)

# ============================================================================
# FLASK APPLICATION SETUP
# ============================================================================

app = Flask(__name__)

# Secret key for session management (generate random key for security)
# In production, store this in environment variable!
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Session configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def check_keys_exist():
    """
    Check if all required cryptographic keys exist.
    
    Returns:
        bool: True if all keys exist, False otherwise
    """
    required_keys = [
        'keys/kyber_public.key',
        'keys/kyber_secret.key',
        'keys/signature_public.key',
        'keys/signature_secret.key'
    ]
    
    for key_file in required_keys:
        if not os.path.exists(key_file):
            return False
    
    return True


def load_signature_algorithm_name():
    """
    Load the signature algorithm name from file.
    Returns 'ML-DSA-44' or 'Dilithium2' based on what was generated.
    """
    sig_name_file = 'keys/signature_algorithm.txt'
    if os.path.exists(sig_name_file):
        with open(sig_name_file, 'r') as f:
            return f.read().strip()
    else:
        # Default to ML-DSA-44 if file doesn't exist (backwards compatibility)
        return 'ML-DSA-44'


def login_required(f):
    """
    Decorator to require user login for routes.
    
    Usage:
        @app.route('/protected')
        @login_required
        def protected_route():
            ...
    """
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    
    return decorated_function


def admin_required(f):
    """
    Decorator to require admin login for routes.
    """
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Admin login required', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    
    return decorated_function


# ============================================================================
# PUBLIC ROUTES
# ============================================================================

@app.route('/')
def index():
    """
    Home page - landing page for the voting system.
    Shows welcome message and navigation options.
    """
    # Check if voting is open
    voting_open = db.is_voting_open()
    
    # Get statistics for display
    stats = db.get_statistics()
    
    # Import to check if liboqs is available
    import crypto_utils
    
    return render_template('index.html', 
                         voting_open=voting_open,
                         stats=stats,
                         simulation_mode=not crypto_utils.LIBOQS_AVAILABLE)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    User registration page.
    
    GET: Display registration form
    POST: Process registration and create new user account
    """
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate inputs
        valid_username, username_msg = validate_username(username)
        if not valid_username:
            flash(username_msg, 'danger')
            return redirect(url_for('register'))
        
        valid_email, email_msg = validate_email(email)
        if not valid_email:
            flash(email_msg, 'danger')
            return redirect(url_for('register'))
        
        valid_password, password_msg = validate_password(password)
        if not valid_password:
            flash(password_msg, 'danger')
            return redirect(url_for('register'))
        
        # Check password confirmation
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        # Create user account
        success, message = db.create_user(username, email, password)
        
        if success:
            # Login the user automatically
            user_success, user_data = db.verify_user_login(username, password)
            if user_success:
                session['user_id'] = user_data['id']
                session['username'] = user_data['username']
                
                flash('Registration successful! Now register your face (optional).', 'success')
                # Redirect to registration page with face registration prompt
                return redirect(url_for('register') + '?registered=true')
            else:
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))
        else:
            flash(message, 'danger')
            return redirect(url_for('register'))
    
    # GET request - show registration form
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login page.
    
    GET: Display login form
    POST: Verify credentials and create session
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Verify credentials
        success, user_data = db.verify_user_login(username, password)
        
        if success:
            # Create session
            session['user_id'] = user_data['id']
            session['username'] = user_data['username']
            
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('vote_page'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
    
    # GET request - show login form
    return render_template('login.html')


@app.route('/logout')
def logout():
    """
    Logout current user and destroy session.
    """
    username = session.get('username', 'User')
    session.clear()
    flash(f'Goodbye, {username}!', 'info')
    return redirect(url_for('index'))


# ============================================================================
# FACIAL RECOGNITION ROUTES
# ============================================================================

@app.route('/register_face', methods=['POST'])
@login_required
def register_face():
    """
    Register face data for logged-in user.
    Receives base64 image, extracts features, encrypts with Kyber-512.
    """
    try:
        # Get image data from request
        data = request.get_json()
        image_base64 = data.get('image')
        
        if not image_base64:
            return jsonify({'success': False, 'message': 'No image provided'}), 400
        
        # Check if face recognition is available
        if not face.is_face_recognition_available():
            return jsonify({
                'success': False,
                'message': 'Face recognition not available. Install DeepFace.'
            }), 503
        
        # Load Kyber public key
        kyber_public = crypto.load_key_from_file('keys/kyber_public.key')
        
        # Register face (extract and encrypt)
        result = face.register_face(image_base64, kyber_public)
        
        if result['success']:
            # Save encrypted face data to database
            # ✅ FIX: Unpack face_data dictionary into individual arguments
            face_data = result['face_data']
            success, message = db.save_user_face_data(
                user_id=session['user_id'],
                kyber_ciphertext=face_data['kyber_ciphertext'],
                encrypted_data=face_data['encrypted_data'],
                nonce=face_data['nonce']
            )
            
            if success:
                return jsonify({
                    'success': True,
                    'message': 'Face registered successfully!'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': message  # ✅ FIX: Use message from database
                }), 500
        else:
            return jsonify({
                'success': False,
                'message': result['message']
            }), 400
    
    except Exception as e:
        print(f"✗ Face registration error: {e}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500


@app.route('/verify_face', methods=['POST'])
def verify_face_login():
    """
    Verify face for login authentication.
    """
    try:
        # Get data from request
        data = request.get_json()
        username = data.get('username')
        image_base64 = data.get('image')
        
        if not username or not image_base64:
            return jsonify({
                'success': False,
                'message': 'Username and image required'
            }), 400
        
        # Check if face recognition available
        if not face.is_face_recognition_available():
            return jsonify({
                'success': False,
                'message': 'Face recognition not available'
            }), 503
        
        # Get user data including face
        user = db.get_user_by_username_with_face(username)
        
        if not user:
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 404
        
        if not user.get('face_registered'):
            return jsonify({
                'success': False,
                'message': 'No face data registered for this user'
            }), 400
        
        # Load Kyber secret key
        kyber_secret = crypto.load_key_from_file('keys/kyber_secret.key')
        
        # Verify face
        result = face.verify_face(
            image_base64,
            user['face_data'],
            kyber_secret
        )
        
        if result['success']:
            # Create session (face verification successful)
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['face_verified'] = True
            
            return jsonify({
                'success': True,
                'message': 'Face verified successfully!',
                'similarity': result['similarity']
            })
        else:
            return jsonify({
                'success': False,
                'message': result['message'],
                'similarity': result['similarity']
            })
    
    except Exception as e:
        print(f"✗ Face verification error: {e}")
        return jsonify({
            'success': False,
            'message': f'Verification error: {str(e)}'
        }), 500


@app.route('/check_face_status')
@login_required
def check_face_status():
    """
    Check if current user has face data registered.
    """
    try:
        user_face = db.get_user_face_data(session['user_id'])
        
        return jsonify({
            'face_registered': user_face is not None,
            'face_recognition_available': face.is_face_recognition_available()
        })
    
    except Exception as e:
        return jsonify({
            'face_registered': False,
            'face_recognition_available': False,
            'error': str(e)
        }), 500


# ============================================================================
# VOTING ROUTES
# ============================================================================

@app.route('/vote')
@login_required
def vote_page():
    """
    Display voting page with list of candidates.
    Only accessible to logged-in users who haven't voted yet.
    """
    # Check if user has already voted
    user = db.get_user_by_id(session['user_id'])
    if user['has_voted']:
        flash('You have already voted!', 'warning')
        return redirect(url_for('index'))
    
    # Check if voting is open
    if not db.is_voting_open():
        flash('Voting is currently closed', 'warning')
        return redirect(url_for('index'))
    
    # Get all candidates
    candidates = db.get_all_candidates()
    
    if not candidates:
        flash('No candidates available. Please contact admin.', 'warning')
        return redirect(url_for('index'))
    
    # Check if user has face registered
    user_face = db.get_user_face_data(session['user_id'])
    face_registered = user_face is not None
    face_available = face.is_face_recognition_available()
    
    return render_template('vote.html', 
                         candidates=candidates,
                         face_registered=face_registered,
                         face_available=face_available)


@app.route('/cast_vote', methods=['POST'])
@login_required
def cast_vote():
    """
    Process vote submission with quantum-safe encryption and signing.
    
    Steps:
    1. Validate user hasn't voted
    2. Get candidate selection
    3. Create vote data (anonymous - no user ID!)
    4. Encrypt with Kyber-512
    5. Sign with quantum-safe signature
    6. Generate receipt code
    7. Save to database
    8. Mark user as voted
    9. Show receipt
    """
    try:
        # Step 1: Verify user hasn't voted
        user = db.get_user_by_id(session['user_id'])
        if user['has_voted']:
            flash('You have already voted!', 'danger')
            return redirect(url_for('index'))
        
        # Check if voting is open
        if not db.is_voting_open():
            flash('Voting is currently closed', 'danger')
            return redirect(url_for('index'))
        
        # Step 2: Get candidate selection
        candidate_id = request.form.get('candidate_id')
        if not candidate_id:
            flash('Please select a candidate', 'danger')
            return redirect(url_for('vote_page'))
        
        # Step 3: Prepare vote data (ANONYMOUS - no user ID!)
        vote_data = {
            'candidate_id': int(candidate_id),
            'timestamp': datetime.now().isoformat(),
            'random_token': secrets.token_hex(16)  # For additional anonymity
        }
        
        # Step 4: Load Kyber public key and encrypt
        kyber_public = crypto.load_key_from_file('keys/kyber_public.key')
        kyber_ciphertext, encrypted_data, nonce = crypto.encrypt_vote_kyber(
            vote_data, kyber_public
        )
        
        # Step 5: Load signature secret key and sign
        # Combine all encrypted components for signing
        sig_secret = crypto.load_key_from_file('keys/signature_secret.key')
        sig_name = load_signature_algorithm_name()
        message_to_sign = kyber_ciphertext + encrypted_data + nonce
        signature = crypto.sign_vote(message_to_sign, sig_secret, sig_name)
        
        # Step 6: Generate unique receipt code
        vote_package = message_to_sign + signature
        receipt_code = crypto.generate_receipt_code(vote_package)
        
        # Step 7: Save to database
        success, message = db.save_vote(
            kyber_ciphertext, encrypted_data, nonce, signature, receipt_code
        )
        
        if not success:
            flash(message, 'danger')
            return redirect(url_for('vote_page'))
        
        # Step 8: Mark user as voted (prevent double voting)
        db.mark_user_voted(session['user_id'])
        
        # Clear face verification flag from session
        session.pop('face_verified_for_vote', None)
        
        # Step 9: Show receipt
        flash('Vote cast successfully!', 'success')
        return render_template('receipt.html', 
                             receipt_code=receipt_code,
                             timestamp=datetime.now())
    
    except Exception as e:
        print(f"✗ Error casting vote: {e}")
        flash('Error casting vote. Please try again.', 'danger')
        return redirect(url_for('vote_page'))


@app.route('/verify_face_for_vote', methods=['POST'])
@login_required
def verify_face_for_vote():
    """
    Verify face before allowing vote to be cast.
    """
    try:
        # Get image data
        data = request.get_json()
        image_base64 = data.get('image')
        
        if not image_base64:
            return jsonify({'success': False, 'message': 'No image provided'}), 400
        
        # Check if face recognition available
        if not face.is_face_recognition_available():
            return jsonify({
                'success': False,
                'message': 'Face recognition not available'
            }), 503
        
        # Get user's stored face data
        user_face = db.get_user_face_data(session['user_id'])
        
        if not user_face:
            return jsonify({
                'success': False,
                'message': 'No face data registered'
            }), 400
        
        # Load Kyber secret key
        kyber_secret = crypto.load_key_from_file('keys/kyber_secret.key')
        
        # Verify face
        result = face.verify_face(image_base64, user_face, kyber_secret)
        
        if result['success']:
            # Set flag in session that face was verified for this vote
            session['face_verified_for_vote'] = True
            
            return jsonify({
                'success': True,
                'message': 'Face verified! You can now cast your vote.',
                'similarity': result['similarity']
            })
        else:
            return jsonify({
                'success': False,
                'message': result['message'],
                'similarity': result['similarity']
            })
    
    except Exception as e:
        print(f"✗ Face verification for vote error: {e}")
        return jsonify({
            'success': False,
            'message': f'Verification error: {str(e)}'
        }), 500


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    """
    Verify a vote using receipt code.
    
    GET: Display verification form
    POST: Look up vote and verify signature
    """
    if request.method == 'POST':
        receipt_code = request.form.get('receipt_code', '').strip().upper()
        
        if not receipt_code:
            flash('Please enter a receipt code', 'warning')
            return redirect(url_for('verify'))
        
        # Look up vote
        vote = db.get_vote_by_receipt(receipt_code)
        
        if not vote:
            flash('Receipt code not found', 'danger')
            return redirect(url_for('verify'))
        
        # Verify signature
        try:
            sig_public = crypto.load_key_from_file('keys/signature_public.key')
            sig_name = load_signature_algorithm_name()
            message_to_verify = vote['kyber_ciphertext'] + vote['encrypted_data'] + vote['nonce']
            
            is_valid = crypto.verify_vote_signature(
                message_to_verify,
                vote['signature'],
                sig_public,
                sig_name
            )
            
            if is_valid:
                return render_template('verify.html',
                                     verified=True,
                                     vote=vote,
                                     receipt_code=receipt_code)
            else:
                flash('Vote signature verification failed! Vote may be tampered.', 'danger')
                return render_template('verify.html',
                                     verified=False,
                                     receipt_code=receipt_code)
        
        except Exception as e:
            print(f"✗ Verification error: {e}")
            flash('Error verifying vote', 'danger')
            return redirect(url_for('verify'))
    
    # GET request - show verification form
    return render_template('verify.html', verified=None)


# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """
    Admin login page (separate from regular user login).
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Verify admin credentials
        success, admin_data = db.verify_admin_login(username, password)
        
        if success:
            # Create admin session
            session['admin_id'] = admin_data['id']
            session['admin_username'] = admin_data['username']
            
            flash(f'Welcome, Admin {username}!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials', 'danger')
            return redirect(url_for('admin_login'))
    
    # GET request
    return render_template('admin_login.html')


@app.route('/admin/logout')
def admin_logout():
    """
    Logout admin and destroy session.
    """
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    flash('Admin logged out', 'info')
    return redirect(url_for('index'))


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """
    Admin dashboard showing statistics and management options.
    """
    # Get statistics
    stats = db.get_statistics()
    
    # Get all candidates
    candidates = db.get_all_candidates()
    
    return render_template('admin_dashboard.html',
                         stats=stats,
                         candidates=candidates)


@app.route('/admin/add_candidate', methods=['POST'])
@admin_required
def add_candidate():
    """
    Add a new candidate (admin only).
    """
    name = request.form.get('name', '').strip()
    party = request.form.get('party', '').strip()
    description = request.form.get('description', '').strip()
    
    # Validate
    valid, message = validate_candidate_data(name, party)
    if not valid:
        flash(message, 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Add candidate
    success, message = db.add_candidate(name, party, description)
    
    if success:
        flash(f'Candidate "{name}" added successfully', 'success')
    else:
        flash(message, 'danger')
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_candidate/<int:candidate_id>', methods=['POST'])
@admin_required
def delete_candidate(candidate_id):
    """
    Delete a candidate (admin only).
    """
    success = db.delete_candidate(candidate_id)
    
    if success:
        flash('Candidate deleted', 'success')
    else:
        flash('Error deleting candidate', 'danger')
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/close_voting', methods=['POST'])
@admin_required
def close_voting():
    """
    Close the voting (no more votes can be cast).
    """
    success = db.close_voting()
    
    if success:
        flash('Voting closed successfully', 'success')
    else:
        flash('Error closing voting', 'danger')
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/open_voting', methods=['POST'])
@admin_required
def open_voting():
    """
    Open/reopen voting.
    """
    success = db.open_voting()
    
    if success:
        flash('Voting opened successfully', 'success')
    else:
        flash('Error opening voting', 'danger')
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/tally', methods=['GET', 'POST'])
@admin_required
def tally_votes():
    """
    Decrypt and count all votes (admin only).
    
    This is the most critical admin function - it decrypts all votes
    using the Kyber secret key and tallies the results.
    """
    if request.method == 'POST':
        try:
            # Get all encrypted votes
            votes = db.get_all_votes()
            
            if not votes:
                flash('No votes to tally', 'warning')
                return redirect(url_for('admin_dashboard'))
            
            # Load Kyber secret key
            kyber_secret = crypto.load_key_from_file('keys/kyber_secret.key')
            
            # Decrypt and count votes
            vote_counts = {}
            decrypted_votes = []
            
            for vote in votes:
                try:
                    # Decrypt vote
                    decrypted_vote_data = crypto.decrypt_vote_kyber(
                        vote['kyber_ciphertext'],
                        vote['encrypted_data'],
                        vote['nonce'],
                        kyber_secret
                    )
                    
                    # Count vote
                    candidate_id = decrypted_vote_data['candidate_id']
                    vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1
                    
                    # Store for display
                    decrypted_votes.append({
                        'candidate_id': candidate_id,
                        'timestamp': decrypted_vote_data['timestamp'],
                        'receipt_code': vote['receipt_code']
                    })
                
                except Exception as e:
                    print(f"✗ Error decrypting vote {vote['id']}: {e}")
                    continue
            
            # Get candidate information
            candidates = db.get_all_candidates()
            candidate_dict = {c['id']: c for c in candidates}
            
            # Calculate results
            total_votes = len(decrypted_votes)
            results = []
            
            for candidate_id, count in vote_counts.items():
                if candidate_id in candidate_dict:
                    candidate = candidate_dict[candidate_id]
                    percentage = (count / total_votes * 100) if total_votes > 0 else 0
                    
                    results.append({
                        'candidate_id': candidate_id,
                        'name': candidate['name'],
                        'party': candidate['party'],
                        'votes': count,
                        'percentage': round(percentage, 2)
                    })
            
            # Sort by vote count (descending)
            results.sort(key=lambda x: x['votes'], reverse=True)
            
            return render_template('admin_dashboard.html',
                                 stats=db.get_statistics(),
                                 candidates=candidates,
                                 results=results,
                                 total_votes=total_votes,
                                 show_results=True)
        
        except Exception as e:
            print(f"✗ Error tallying votes: {e}")
            flash('Error tallying votes', 'danger')
            return redirect(url_for('admin_dashboard'))
    
    # GET request - show tally button
    return redirect(url_for('admin_dashboard'))


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('index.html'), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    flash('An internal error occurred', 'danger')
    return redirect(url_for('index'))


# ============================================================================
# STARTUP CHECKS
# ============================================================================

def perform_startup_checks():
    """
    Perform checks before starting the application.
    """
    print("\n" + "="*70)
    print("QUANTUM-SAFE E-VOTING SYSTEM")
    print("="*70 + "\n")
    
    # Check if database exists
    if not os.path.exists(DATABASE_PATH):
        print("⚠ Database not found")
        print("  Creating database...")
        db.init_database()
        print()
    else:
        print("✓ Database found")
    
    # Check if keys exist
    if not check_keys_exist():
        print("✗ Cryptographic keys not found!")
        print("  Please run: python generate_keys.py")
        print()
        return False
    else:
        print("✓ Cryptographic keys found")
    
    print("\n" + "="*70)
    print("SYSTEM READY")
    print("="*70)
    print("\nDefault Admin Credentials:")
    print("  Username: admin")
    print("  Password: admin123")
    print("\n⚠ CHANGE ADMIN PASSWORD IN PRODUCTION!")
    print("\nStarting server at: http://127.0.0.1:5000")
    print("="*70 + "\n")
    
    return True


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    # Perform startup checks
    if not perform_startup_checks():
        sys.exit(1)
    
    # Run Flask development server
    # For production, use proper WSGI server (gunicorn, waitress, etc.)
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True  # Set to False in production!
    )