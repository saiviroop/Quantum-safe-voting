# ============================================================================
# QUANTUM-SAFE E-VOTING SYSTEM - FACIAL RECOGNITION UTILITIES
# ============================================================================
# File: face_utils.py
# Purpose: Handle face capture, encryption, and verification with Kyber-512
# ============================================================================

import os
import base64
import json
import numpy as np
from io import BytesIO
from PIL import Image
import crypto_utils as crypto

# Import DeepFace for facial recognition
try:
    from deepface import DeepFace
    DEEPFACE_AVAILABLE = True
    print("✓ DeepFace available for facial recognition")
except ImportError:
    DEEPFACE_AVAILABLE = False
    print("⚠ DeepFace not available - face recognition disabled")

# ============================================================================
# CONFIGURATION
# ============================================================================

# Face verification threshold (0.0 to 1.0)
# Lower = stricter matching, Higher = more lenient
FACE_MATCH_THRESHOLD = 0.70  # 70% similarity required

# Supported image formats
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Face detection backend (use OpenCV for speed)
FACE_DETECTOR_BACKEND = 'opencv'

# Face recognition model (use Facenet for accuracy)
FACE_MODEL = 'Facenet'

# ============================================================================
# FACE CAPTURE & PROCESSING
# ============================================================================

def process_base64_image(base64_string):
    """
    Convert base64 image string to PIL Image.
    
    Args:
        base64_string (str): Base64 encoded image data
        
    Returns:
        PIL.Image: Processed image object
    """
    try:
        # Remove data URL prefix if present
        if ',' in base64_string:
            base64_string = base64_string.split(',')[1]
        
        # Decode base64 to bytes
        image_bytes = base64.b64decode(base64_string)
        
        # Convert to PIL Image
        image = Image.open(BytesIO(image_bytes))
        
        # Convert to RGB if needed
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        return image
    
    except Exception as e:
        print(f"✗ Error processing base64 image: {e}")
        raise ValueError("Invalid image data")


def save_temp_image(image, filename='temp_face.jpg'):
    """
    Save image temporarily for DeepFace processing.
    
    Args:
        image (PIL.Image): Image to save
        filename (str): Temporary filename
        
    Returns:
        str: Path to saved image
    """
    try:
        temp_dir = 'temp'
        os.makedirs(temp_dir, exist_ok=True)
        
        temp_path = os.path.join(temp_dir, filename)
        image.save(temp_path, 'JPEG', quality=95)
        
        return temp_path
    
    except Exception as e:
        print(f"✗ Error saving temp image: {e}")
        raise


def extract_face_embedding(image_path):
    """
    Extract face embedding (facial features) from image using DeepFace.
    
    Args:
        image_path (str): Path to image file
        
    Returns:
        np.ndarray: Face embedding vector (128 dimensions)
        
    Raises:
        ValueError: If no face detected or DeepFace not available
    """
    if not DEEPFACE_AVAILABLE:
        raise ValueError("DeepFace library not installed")
    
    try:
        # Extract face embedding using DeepFace
        embedding_objs = DeepFace.represent(
            img_path=image_path,
            model_name=FACE_MODEL,
            detector_backend=FACE_DETECTOR_BACKEND,
            enforce_detection=True
        )
        
        # Get the first face detected
        if not embedding_objs:
            raise ValueError("No face detected in image")
        
        embedding = np.array(embedding_objs[0]['embedding'])
        
        print(f"✓ Face embedding extracted: {len(embedding)} dimensions")
        return embedding
    
    except Exception as e:
        print(f"✗ Error extracting face embedding: {e}")
        raise ValueError(f"Could not detect face: {str(e)}")


def cleanup_temp_files():
    """Remove temporary image files."""
    try:
        temp_dir = 'temp'
        if os.path.exists(temp_dir):
            for file in os.listdir(temp_dir):
                if file.endswith(('.jpg', '.jpeg', '.png')):
                    os.remove(os.path.join(temp_dir, file))
    except Exception as e:
        print(f"⚠ Could not cleanup temp files: {e}")


# ============================================================================
# QUANTUM-SAFE FACE DATA ENCRYPTION
# ============================================================================

def encrypt_face_embedding(embedding, kyber_public_key):
    """
    Encrypt face embedding using Kyber-512 quantum-safe encryption.
    
    Process:
    1. Convert numpy array to JSON
    2. Encrypt with Kyber-512 + AES-GCM
    3. Return encrypted components
    
    Args:
        embedding (np.ndarray): Face embedding vector
        kyber_public_key (bytes): Kyber-512 public key
        
    Returns:
        tuple: (kyber_ciphertext, encrypted_data, nonce)
    """
    try:
        # Convert embedding to serializable format
        embedding_data = {
            'embedding': embedding.tolist(),  # Convert numpy to list
            'dimensions': len(embedding),
            'model': FACE_MODEL
        }
        
        # Encrypt with Kyber-512
        kyber_ct, encrypted, nonce = crypto.encrypt_vote_kyber(
            embedding_data,
            kyber_public_key
        )
        
        print(f"✓ Face embedding encrypted with Kyber-512")
        print(f"  - Kyber ciphertext: {len(kyber_ct)} bytes")
        print(f"  - Encrypted data: {len(encrypted)} bytes")
        
        return kyber_ct, encrypted, nonce
    
    except Exception as e:
        print(f"✗ Error encrypting face embedding: {e}")
        raise


def decrypt_face_embedding(kyber_ciphertext, encrypted_data, nonce, kyber_secret_key):
    """
    Decrypt face embedding using Kyber-512.
    
    Args:
        kyber_ciphertext (bytes): Kyber ciphertext
        encrypted_data (bytes): Encrypted embedding data
        nonce (bytes): AES-GCM nonce
        kyber_secret_key (bytes): Kyber-512 secret key
        
    Returns:
        np.ndarray: Decrypted face embedding
    """
    try:
        # Decrypt with Kyber-512
        embedding_data = crypto.decrypt_vote_kyber(
            kyber_ciphertext,
            encrypted_data,
            nonce,
            kyber_secret_key
        )
        
        # Convert back to numpy array
        embedding = np.array(embedding_data['embedding'])
        
        print(f"✓ Face embedding decrypted")
        return embedding
    
    except Exception as e:
        print(f"✗ Error decrypting face embedding: {e}")
        raise


# ============================================================================
# FACE VERIFICATION
# ============================================================================

def calculate_face_similarity(embedding1, embedding2):
    """
    Calculate similarity between two face embeddings.
    
    Uses cosine similarity for comparison.
    
    Args:
        embedding1 (np.ndarray): First face embedding
        embedding2 (np.ndarray): Second face embedding
        
    Returns:
        float: Similarity score (0.0 to 1.0)
    """
    try:
        # Calculate cosine similarity
        dot_product = np.dot(embedding1, embedding2)
        norm1 = np.linalg.norm(embedding1)
        norm2 = np.linalg.norm(embedding2)
        
        similarity = dot_product / (norm1 * norm2)
        
        # Convert to 0-1 range (cosine similarity is -1 to 1)
        similarity = (similarity + 1) / 2
        
        return float(similarity)
    
    except Exception as e:
        print(f"✗ Error calculating similarity: {e}")
        return 0.0


def verify_face(captured_image_base64, stored_encrypted_face, kyber_secret_key):
    """
    Verify captured face against stored encrypted face data.
    
    Complete verification flow:
    1. Process captured image
    2. Extract face embedding from captured image
    3. Decrypt stored face embedding
    4. Compare embeddings
    5. Return match result
    
    Args:
        captured_image_base64 (str): Base64 encoded captured image
        stored_encrypted_face (dict): Stored encrypted face data
            - kyber_ciphertext
            - encrypted_data
            - nonce
        kyber_secret_key (bytes): Kyber-512 secret key for decryption
        
    Returns:
        dict: Verification result
            - success (bool): Whether verification succeeded
            - similarity (float): Face similarity score (0-1)
            - message (str): Result message
    """
    try:
        # Step 1: Process captured image
        print("Step 1: Processing captured image...")
        captured_image = process_base64_image(captured_image_base64)
        temp_path = save_temp_image(captured_image, 'verify_face.jpg')
        
        # Step 2: Extract embedding from captured image
        print("Step 2: Extracting face embedding...")
        captured_embedding = extract_face_embedding(temp_path)
        
        # Step 3: Decrypt stored face embedding
        print("Step 3: Decrypting stored face data...")
        stored_embedding = decrypt_face_embedding(
            stored_encrypted_face['kyber_ciphertext'],
            stored_encrypted_face['encrypted_data'],
            stored_encrypted_face['nonce'],
            kyber_secret_key
        )
        
        # Step 4: Calculate similarity
        print("Step 4: Comparing faces...")
        similarity = calculate_face_similarity(captured_embedding, stored_embedding)
        
        # Step 5: Determine match
        is_match = similarity >= FACE_MATCH_THRESHOLD
        
        # Cleanup
        cleanup_temp_files()
        
        result = {
            'success': is_match,
            'similarity': round(similarity * 100, 2),  # Convert to percentage
            'threshold': round(FACE_MATCH_THRESHOLD * 100, 2),
            'message': f"Face match: {similarity*100:.1f}% (threshold: {FACE_MATCH_THRESHOLD*100:.0f}%)"
        }
        
        if is_match:
            print(f"✓ Face verified: {similarity*100:.1f}% similarity")
        else:
            print(f"✗ Face verification failed: {similarity*100:.1f}% similarity")
        
        return result
    
    except ValueError as e:
        # Face detection error
        cleanup_temp_files()
        return {
            'success': False,
            'similarity': 0.0,
            'threshold': FACE_MATCH_THRESHOLD * 100,
            'message': str(e)
        }
    
    except Exception as e:
        # Other errors
        cleanup_temp_files()
        print(f"✗ Face verification error: {e}")
        return {
            'success': False,
            'similarity': 0.0,
            'threshold': FACE_MATCH_THRESHOLD * 100,
            'message': f"Verification error: {str(e)}"
        }


# ============================================================================
# FACE REGISTRATION
# ============================================================================

def register_face(image_base64, kyber_public_key):
    """
    Register a new face during user registration.
    
    Process:
    1. Process and validate image
    2. Extract face embedding
    3. Encrypt embedding with Kyber-512
    4. Return encrypted face data
    
    Args:
        image_base64 (str): Base64 encoded face image
        kyber_public_key (bytes): Kyber-512 public key
        
    Returns:
        dict: Encrypted face data or error
            - success (bool)
            - face_data (dict): Encrypted face components
            - message (str)
    """
    try:
        # Step 1: Process image
        print("Processing face image for registration...")
        image = process_base64_image(image_base64)
        temp_path = save_temp_image(image, 'register_face.jpg')
        
        # Step 2: Extract face embedding
        print("Extracting facial features...")
        embedding = extract_face_embedding(temp_path)
        
        # Step 3: Encrypt with Kyber-512
        print("Encrypting face data with Kyber-512...")
        kyber_ct, encrypted, nonce = encrypt_face_embedding(
            embedding,
            kyber_public_key
        )
        
        # Cleanup
        cleanup_temp_files()
        
        return {
            'success': True,
            'face_data': {
                'kyber_ciphertext': kyber_ct,
                'encrypted_data': encrypted,
                'nonce': nonce
            },
            'message': 'Face registered successfully'
        }
    
    except ValueError as e:
        # Face detection error
        cleanup_temp_files()
        return {
            'success': False,
            'face_data': None,
            'message': str(e)
        }
    
    except Exception as e:
        # Other errors
        cleanup_temp_files()
        print(f"✗ Face registration error: {e}")
        return {
            'success': False,
            'face_data': None,
            'message': f"Registration error: {str(e)}"
        }


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def is_face_recognition_available():
    """
    Check if face recognition is available.
    
    Returns:
        bool: True if DeepFace is available
    """
    return DEEPFACE_AVAILABLE


def get_face_instructions():
    """
    Get user instructions for face capture.
    
    Returns:
        dict: Instructions for optimal face capture
    """
    return {
        'lighting': 'Ensure good lighting on your face',
        'position': 'Look directly at the camera',
        'distance': 'Keep your face centered in the frame',
        'expression': 'Use a neutral expression',
        'glasses': 'Remove sunglasses if possible',
        'background': 'Use a plain background if possible'
    }


# ============================================================================
# TEST FUNCTION
# ============================================================================

def test_face_system():
    """
    Test facial recognition system.
    """
    print("\n" + "="*70)
    print("TESTING FACIAL RECOGNITION SYSTEM")
    print("="*70 + "\n")
    
    if not DEEPFACE_AVAILABLE:
        print("✗ DeepFace not available - install with:")
        print("  pip install deepface")
        return False
    
    print("✓ DeepFace is available")
    print(f"✓ Face model: {FACE_MODEL}")
    print(f"✓ Detector backend: {FACE_DETECTOR_BACKEND}")
    print(f"✓ Match threshold: {FACE_MATCH_THRESHOLD*100}%")
    
    print("\n" + "="*70)
    print("Face recognition system ready!")
    print("="*70 + "\n")
    
    return True


if __name__ == "__main__":
    test_face_system()