# ============================================================================
# QUANTUM-SAFE E-VOTING SYSTEM - DATA MODELS
# ============================================================================
# File: models.py
# Purpose: Data classes representing users, candidates, votes, and admins
# ============================================================================

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# ============================================================================
# USER MODEL
# ============================================================================

@dataclass
class User:
    """
    Represents a regular voter in the system.
    
    Attributes:
        id: Unique user identifier (auto-generated)
        username: Unique username for login
        email: User's email address
        password_hash: Bcrypt hash of password (never store plain text!)
        has_voted: Boolean flag indicating if user has cast their vote
        is_admin: Boolean flag (always False for regular users)
        created_at: Timestamp of account creation
    """
    id: int
    username: str
    email: str
    password_hash: str
    has_voted: bool = False
    is_admin: bool = False
    created_at: datetime = None
    
    def __post_init__(self):
        """Set default timestamp if not provided."""
        if self.created_at is None:
            self.created_at = datetime.now()
    
    def to_dict(self):
        """Convert user object to dictionary (exclude password hash)."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'has_voted': self.has_voted,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


# ============================================================================
# ADMIN MODEL
# ============================================================================

@dataclass
class Admin:
    """
    Represents an admin user with elevated privileges.
    
    Admin users are separate from regular voters and cannot vote themselves.
    This separation ensures election integrity.
    
    Attributes:
        id: Unique admin identifier
        username: Admin username for login
        password_hash: Bcrypt hash of admin password
        created_at: Timestamp of admin account creation
    """
    id: int
    username: str
    password_hash: str
    created_at: datetime = None
    
    def __post_init__(self):
        """Set default timestamp if not provided."""
        if self.created_at is None:
            self.created_at = datetime.now()
    
    def to_dict(self):
        """Convert admin object to dictionary (exclude password hash)."""
        return {
            'id': self.id,
            'username': self.username,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


# ============================================================================
# CANDIDATE MODEL
# ============================================================================

@dataclass
class Candidate:
    """
    Represents an election candidate.
    
    Attributes:
        id: Unique candidate identifier
        name: Full name of candidate
        party: Political party affiliation
        description: Optional bio or platform description
        created_at: Timestamp when candidate was added
    """
    id: int
    name: str
    party: str
    description: Optional[str] = ""
    created_at: datetime = None
    
    def __post_init__(self):
        """Set default timestamp if not provided."""
        if self.created_at is None:
            self.created_at = datetime.now()
    
    def to_dict(self):
        """Convert candidate object to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'party': self.party,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


# ============================================================================
# VOTE MODEL
# ============================================================================

@dataclass
class Vote:
    """
    Represents an encrypted, anonymous vote.
    
    Votes are encrypted with Kyber-512 and signed with Dilithium-2.
    No link exists between the vote content and voter identity.
    
    Attributes:
        id: Unique vote identifier
        kyber_ciphertext: Kyber KEM ciphertext (768 bytes)
        encrypted_data: AES-GCM encrypted vote data
        nonce: AES-GCM nonce (12 bytes)
        signature: Dilithium-2 signature (2420 bytes)
        receipt_code: Unique 12-character receipt code for verification
        timestamp: When vote was cast
    """
    id: int
    kyber_ciphertext: bytes
    encrypted_data: bytes
    nonce: bytes
    signature: bytes
    receipt_code: str
    timestamp: datetime = None
    
    def __post_init__(self):
        """Set default timestamp if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self):
        """
        Convert vote object to dictionary.
        Note: Binary data (encryption/signature) is not included in dict form.
        """
        return {
            'id': self.id,
            'receipt_code': self.receipt_code,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


# ============================================================================
# VOTING STATUS MODEL
# ============================================================================

@dataclass
class VotingStatus:
    """
    Represents the current status of the election.
    
    Controls whether voting is open (accepting votes) or closed.
    Only one record should exist with id=1.
    
    Attributes:
        id: Always 1 (singleton record)
        is_open: Boolean indicating if voting is currently open
        opened_at: Timestamp when voting was opened
        closed_at: Timestamp when voting was closed (None if still open)
    """
    id: int = 1
    is_open: bool = True
    opened_at: datetime = None
    closed_at: Optional[datetime] = None
    
    def __post_init__(self):
        """Set default opened_at timestamp if not provided."""
        if self.opened_at is None and self.is_open:
            self.opened_at = datetime.now()
    
    def to_dict(self):
        """Convert voting status to dictionary."""
        return {
            'id': self.id,
            'is_open': self.is_open,
            'opened_at': self.opened_at.isoformat() if self.opened_at else None,
            'closed_at': self.closed_at.isoformat() if self.closed_at else None
        }


# ============================================================================
# DECRYPTED VOTE MODEL (FOR ADMIN TALLYING)
# ============================================================================

@dataclass
class DecryptedVote:
    """
    Represents a decrypted vote (used only during admin tallying).
    
    This model is not stored in the database - it's only used in memory
    when the admin decrypts votes to count results.
    
    Attributes:
        candidate_id: ID of the candidate this vote is for
        timestamp: When the vote was cast
        receipt_code: Receipt code for verification
        random_token: Random token for additional anonymity
    """
    candidate_id: int
    timestamp: str
    receipt_code: str
    random_token: str = ""
    
    def to_dict(self):
        """Convert decrypted vote to dictionary."""
        return {
            'candidate_id': self.candidate_id,
            'timestamp': self.timestamp,
            'receipt_code': self.receipt_code
        }


# ============================================================================
# TALLY RESULT MODEL
# ============================================================================

@dataclass
class TallyResult:
    """
    Represents vote count results for a candidate.
    
    Used when displaying election results after tallying.
    
    Attributes:
        candidate_id: ID of the candidate
        candidate_name: Name of the candidate
        party: Political party
        vote_count: Number of votes received
        percentage: Percentage of total votes
    """
    candidate_id: int
    candidate_name: str
    party: str
    vote_count: int
    percentage: float
    
    def to_dict(self):
        """Convert tally result to dictionary."""
        return {
            'candidate_id': self.candidate_id,
            'candidate_name': self.candidate_name,
            'party': self.party,
            'vote_count': self.vote_count,
            'percentage': round(self.percentage, 2)
        }


# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

def validate_username(username: str) -> tuple[bool, str]:
    """
    Validate username format.
    
    Rules:
        - 3-30 characters
        - Only alphanumeric and underscore
        - Must start with a letter
    
    Args:
        username: Username to validate
    
    Returns:
        tuple: (is_valid: bool, error_message: str)
    """
    if not username:
        return False, "Username is required"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    
    if len(username) > 30:
        return False, "Username must be at most 30 characters"
    
    if not username[0].isalpha():
        return False, "Username must start with a letter"
    
    if not username.replace('_', '').isalnum():
        return False, "Username can only contain letters, numbers, and underscores"
    
    return True, ""


def validate_email(email: str) -> tuple[bool, str]:
    """
    Validate email format (basic validation).
    
    Args:
        email: Email address to validate
    
    Returns:
        tuple: (is_valid: bool, error_message: str)
    """
    if not email:
        return False, "Email is required"
    
    if '@' not in email or '.' not in email.split('@')[1]:
        return False, "Invalid email format"
    
    if len(email) > 100:
        return False, "Email is too long"
    
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength.
    
    Rules:
        - At least 8 characters
        - Contains at least one letter and one number
    
    Args:
        password: Password to validate
    
    Returns:
        tuple: (is_valid: bool, error_message: str)
    """
    if not password:
        return False, "Password is required"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    if not (has_letter and has_digit):
        return False, "Password must contain both letters and numbers"
    
    return True, ""


def validate_candidate_data(name: str, party: str) -> tuple[bool, str]:
    """
    Validate candidate data.
    
    Args:
        name: Candidate name
        party: Party affiliation
    
    Returns:
        tuple: (is_valid: bool, error_message: str)
    """
    if not name or not name.strip():
        return False, "Candidate name is required"
    
    if len(name) > 100:
        return False, "Candidate name is too long"
    
    if not party or not party.strip():
        return False, "Party affiliation is required"
    
    if len(party) > 100:
        return False, "Party name is too long"
    
    return True, ""