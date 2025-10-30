// File: 9_script.js
// Frontend JavaScript for Quantum-Safe E-Voting System
// Handles all client-side interactions, form validations, and UI enhancements

// =============================================================================
// GLOBAL VARIABLES AND CONFIGURATION
// =============================================================================

// API Configuration
const API_BASE = window.location.origin;

// Face recognition configuration
let faceStream = null;
let faceVideo = null;
let faceCanvas = null;
let faceContext = null;
let faceDetectionInterval = null;

// Vote confirmation
let selectedCandidateId = null;

// =============================================================================
// INITIALIZATION - Runs when page loads
// =============================================================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 QuantumVote Frontend Initialized');
    
    // Initialize all features
    initializeFormValidations();
    initializeVotingInterface();
    initializeFaceRecognition();
    initializeReceiptVerification();
    initializeAdminPanel();
    initializeAnimations();
    
    // Add smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
});

// =============================================================================
// FORM VALIDATION
// =============================================================================

function initializeFormValidations() {
    // Registration form validation
    const registerForm = document.querySelector('#registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            if (!validateRegistrationForm()) {
                e.preventDefault();
            }
        });
    }
    
    // Login form validation
    const loginForm = document.querySelector('#loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            if (!validateLoginForm()) {
                e.preventDefault();
            }
        });
    }
    
    // Real-time password strength indicator
    const passwordInput = document.querySelector('#password');
    if (passwordInput) {
        passwordInput.addEventListener('input', updatePasswordStrength);
    }
}

function validateRegistrationForm() {
    const username = document.querySelector('#username').value.trim();
    const email = document.querySelector('#email').value.trim();
    const password = document.querySelector('#password').value;
    const confirmPassword = document.querySelector('#confirm_password').value;
    
    // Username validation
    if (username.length < 3) {
        showAlert('Username must be at least 3 characters long', 'danger');
        return false;
    }
    
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        showAlert('Username can only contain letters, numbers, and underscores', 'danger');
        return false;
    }
    
    // Email validation
    if (!isValidEmail(email)) {
        showAlert('Please enter a valid email address', 'danger');
        return false;
    }
    
    // Password validation
    if (password.length < 8) {
        showAlert('Password must be at least 8 characters long', 'danger');
        return false;
    }
    
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
        showAlert('Password must contain uppercase, lowercase, and numbers', 'danger');
        return false;
    }
    
    // Password match validation
    if (password !== confirmPassword) {
        showAlert('Passwords do not match', 'danger');
        return false;
    }
    
    return true;
}

function validateLoginForm() {
    const username = document.querySelector('#username').value.trim();
    const password = document.querySelector('#password').value;
    
    if (!username || !password) {
        showAlert('Please enter both username and password', 'danger');
        return false;
    }
    
    return true;
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function updatePasswordStrength() {
    const password = this.value;
    const strengthIndicator = document.querySelector('#passwordStrength');
    
    if (!strengthIndicator) return;
    
    let strength = 0;
    let strengthText = '';
    let strengthClass = '';
    
    // Calculate strength
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[^a-zA-Z0-9]/.test(password)) strength++;
    
    // Set strength level
    if (strength < 2) {
        strengthText = 'Weak';
        strengthClass = 'bg-danger';
    } else if (strength < 4) {
        strengthText = 'Medium';
        strengthClass = 'bg-warning';
    } else {
        strengthText = 'Strong';
        strengthClass = 'bg-success';
    }
    
    strengthIndicator.innerHTML = `
        <div class="progress mt-2">
            <div class="progress-bar ${strengthClass}" 
                 role="progressbar" 
                 style="width: ${(strength/5)*100}%">
                ${strengthText}
            </div>
        </div>
    `;
}

// =============================================================================
// VOTING INTERFACE
// =============================================================================

function initializeVotingInterface() {
    // Candidate selection
    const candidateCards = document.querySelectorAll('.candidate-card');
    candidateCards.forEach(card => {
        card.addEventListener('click', function() {
            selectCandidate(this);
        });
    });
    
    // Vote confirmation button
    const confirmVoteBtn = document.querySelector('#confirmVoteBtn');
    if (confirmVoteBtn) {
        confirmVoteBtn.addEventListener('click', showVoteConfirmation);
    }
    
    // Final vote submission
    const submitVoteBtn = document.querySelector('#submitVoteBtn');
    if (submitVoteBtn) {
        submitVoteBtn.addEventListener('click', submitVote);
    }
}

function selectCandidate(card) {
    // Remove selection from all cards
    document.querySelectorAll('.candidate-card').forEach(c => {
        c.classList.remove('selected');
    });
    
    // Add selection to clicked card
    card.classList.add('selected');
    
    // Store selected candidate ID
    selectedCandidateId = card.dataset.candidateId;
    
    // Enable vote button
    const voteButton = document.querySelector('#confirmVoteBtn');
    if (voteButton) {
        voteButton.disabled = false;
        voteButton.classList.remove('btn-secondary');
        voteButton.classList.add('btn-success');
    }
    
    // Show selection feedback
    const candidateName = card.querySelector('h4').textContent;
    showAlert(`Selected: ${candidateName}`, 'info');
}

function showVoteConfirmation() {
    if (!selectedCandidateId) {
        showAlert('Please select a candidate first', 'warning');
        return;
    }
    
    const card = document.querySelector(`[data-candidate-id="${selectedCandidateId}"]`);
    const candidateName = card.querySelector('h4').textContent;
    const candidateParty = card.querySelector('.text-muted').textContent;
    
    // Show confirmation modal
    const modalHTML = `
        <div class="modal fade" id="voteConfirmModal" tabindex="-1">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title">
                            <i class="fas fa-vote-yea me-2"></i>
                            Confirm Your Vote
                        </h5>
                        <button type="button" class="btn-close btn-close-white" 
                                data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body text-center py-4">
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            <strong>Warning:</strong> This action cannot be undone!
                        </div>
                        <h4 class="mb-3">You are voting for:</h4>
                        <div class="card border-primary">
                            <div class="card-body">
                                <h3 class="text-primary">${candidateName}</h3>
                                <p class="text-muted mb-0">${candidateParty}</p>
                            </div>
                        </div>
                        <p class="mt-3 text-muted">
                            Once submitted, your vote will be encrypted using quantum-safe 
                            cryptography and cannot be changed.
                        </p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" 
                                data-bs-dismiss="modal">
                            <i class="fas fa-times me-2"></i>Cancel
                        </button>
                        <button type="button" class="btn btn-success" 
                                id="submitVoteBtn" onclick="submitVote()">
                            <i class="fas fa-check me-2"></i>Confirm and Submit Vote
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Remove existing modal if any
    const existingModal = document.querySelector('#voteConfirmModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Add modal to page
    document.body.insertAdjacentHTML('beforeend', modalHTML);
    
    // Show modal
    const modal = new bootstrap.Modal(document.querySelector('#voteConfirmModal'));
    modal.show();
}

async function submitVote() {
    if (!selectedCandidateId) {
        showAlert('No candidate selected', 'danger');
        return;
    }
    
    // Show loading state
    const submitBtn = document.querySelector('#submitVoteBtn');
    const originalText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Encrypting and submitting...';
    
    try {
        // Submit vote to backend
        const response = await fetch('/vote', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `candidate_id=${selectedCandidateId}`
        });
        
        if (response.ok) {
            // Vote successful - redirect to receipt page
            window.location.href = '/receipt';
        } else {
            const error = await response.text();
            showAlert('Failed to submit vote: ' + error, 'danger');
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        }
    } catch (error) {
        console.error('Vote submission error:', error);
        showAlert('An error occurred while submitting your vote', 'danger');
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
    }
}

// =============================================================================
// FACE RECOGNITION
// =============================================================================

function initializeFaceRecognition() {
    // Initialize face capture buttons
    const startFaceBtn = document.querySelector('#startFaceCapture');
    if (startFaceBtn) {
        startFaceBtn.addEventListener('click', startFaceCapture);
    }
    
    const captureFaceBtn = document.querySelector('#captureFaceBtn');
    if (captureFaceBtn) {
        captureFaceBtn.addEventListener('click', captureFace);
    }
    
    const stopFaceBtn = document.querySelector('#stopFaceCapture');
    if (stopFaceBtn) {
        stopFaceBtn.addEventListener('click', stopFaceCapture);
    }
}

async function startFaceCapture(videoElementId = 'faceVideo') {
    try {
        // Get video element
        faceVideo = document.querySelector(`#${videoElementId}`);
        if (!faceVideo) {
            throw new Error('Video element not found');
        }
        
        // Request camera access
        faceStream = await navigator.mediaDevices.getUserMedia({ 
            video: { 
                width: { ideal: 640 },
                height: { ideal: 480 },
                facingMode: 'user'
            } 
        });
        
        // Set video source
        faceVideo.srcObject = faceStream;
        faceVideo.play();
        
        // Show video container
        const videoContainer = faceVideo.closest('.face-capture-container');
        if (videoContainer) {
            videoContainer.classList.remove('d-none');
        }
        
        // Enable capture button
        const captureBtn = document.querySelector('#captureFaceBtn');
        if (captureBtn) {
            captureBtn.disabled = false;
        }
        
        showAlert('Camera started. Please position your face in the frame.', 'success');
        
        // Start face detection (visual feedback)
        startFaceDetection();
        
    } catch (error) {
        console.error('Camera access error:', error);
        showAlert('Could not access camera: ' + error.message, 'danger');
    }
}

function startFaceDetection() {
    // Simple face detection feedback (circle around face area)
    // In production, use face-api.js or similar library
    const videoContainer = faceVideo.closest('.face-capture-container');
    if (videoContainer && !videoContainer.querySelector('.face-guide')) {
        const guide = document.createElement('div');
        guide.className = 'face-guide';
        guide.innerHTML = '<div class="face-guide-circle"></div>';
        videoContainer.appendChild(guide);
    }
}

async function captureFace() {
    if (!faceVideo || !faceStream) {
        showAlert('Please start the camera first', 'warning');
        return;
    }
    
    // Create canvas for capture
    if (!faceCanvas) {
        faceCanvas = document.createElement('canvas');
        faceContext = faceCanvas.getContext('2d');
    }
    
    // Set canvas size to match video
    faceCanvas.width = faceVideo.videoWidth;
    faceCanvas.height = faceVideo.videoHeight;
    
    // Draw current frame to canvas
    faceContext.drawImage(faceVideo, 0, 0);
    
    // Convert canvas to blob
    faceCanvas.toBlob(async (blob) => {
        if (!blob) {
            showAlert('Failed to capture image', 'danger');
            return;
        }
        
        // Show countdown animation
        await showCaptureCountdown();
        
        // Create form data
        const formData = new FormData();
        formData.append('face_image', blob, 'face.jpg');
        
        // Show loading state
        const captureBtn = document.querySelector('#captureFaceBtn');
        const originalText = captureBtn.innerHTML;
        captureBtn.disabled = true;
        captureBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
        
        try {
            // Send to backend for processing
            const response = await fetch('/upload_face', {
                method: 'POST',
                body: formData
            });
            
            if (response.ok) {
                const result = await response.json();
                showAlert('Face captured successfully!', 'success');
                
                // Show preview
                const preview = document.querySelector('#facePreview');
                if (preview) {
                    preview.src = URL.createObjectURL(blob);
                    preview.classList.remove('d-none');
                }
                
                // Stop camera
                stopFaceCapture();
                
                // Enable form submission
                const submitBtn = document.querySelector('button[type="submit"]');
                if (submitBtn) {
                    submitBtn.disabled = false;
                }
            } else {
                const error = await response.json();
                showAlert('Face capture failed: ' + error.message, 'danger');
            }
        } catch (error) {
            console.error('Face upload error:', error);
            showAlert('An error occurred during face capture', 'danger');
        } finally {
            captureBtn.disabled = false;
            captureBtn.innerHTML = originalText;
        }
    }, 'image/jpeg', 0.95);
}

async function showCaptureCountdown() {
    return new Promise((resolve) => {
        let count = 3;
        const videoContainer = faceVideo.closest('.face-capture-container');
        const countdown = document.createElement('div');
        countdown.className = 'face-countdown';
        videoContainer.appendChild(countdown);
        
        const interval = setInterval(() => {
            countdown.textContent = count;
            count--;
            
            if (count < 0) {
                clearInterval(interval);
                countdown.remove();
                resolve();
            }
        }, 1000);
    });
}

function stopFaceCapture() {
    if (faceStream) {
        faceStream.getTracks().forEach(track => track.stop());
        faceStream = null;
    }
    
    if (faceVideo) {
        faceVideo.srcObject = null;
    }
    
    // Hide video container
    const videoContainer = document.querySelector('.face-capture-container');
    if (videoContainer) {
        videoContainer.classList.add('d-none');
    }
    
    // Clear face detection
    if (faceDetectionInterval) {
        clearInterval(faceDetectionInterval);
        faceDetectionInterval = null;
    }
}

// =============================================================================
// RECEIPT VERIFICATION
// =============================================================================

function initializeReceiptVerification() {
    const verifyReceiptBtn = document.querySelector('#verifyReceiptBtn');
    if (verifyReceiptBtn) {
        verifyReceiptBtn.addEventListener('click', verifyReceipt);
    }
    
    // Copy receipt code button
    const copyReceiptBtn = document.querySelector('#copyReceiptCode');
    if (copyReceiptBtn) {
        copyReceiptBtn.addEventListener('click', copyReceiptCode);
    }
    
    // Download receipt button
    const downloadReceiptBtn = document.querySelector('#downloadReceipt');
    if (downloadReceiptBtn) {
        downloadReceiptBtn.addEventListener('click', downloadReceipt);
    }
}

async function verifyReceipt() {
    const receiptCode = document.querySelector('#receiptCodeInput').value.trim();
    
    if (!receiptCode) {
        showAlert('Please enter a receipt code', 'warning');
        return;
    }
    
    // Show loading state
    const verifyBtn = document.querySelector('#verifyReceiptBtn');
    const originalText = verifyBtn.innerHTML;
    verifyBtn.disabled = true;
    verifyBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Verifying...';
    
    try {
        const response = await fetch(`/verify_receipt/${receiptCode}`);
        
        if (response.ok) {
            const result = await response.json();
            displayVerificationResult(result);
        } else {
            showAlert('Receipt not found or invalid', 'danger');
        }
    } catch (error) {
        console.error('Verification error:', error);
        showAlert('An error occurred during verification', 'danger');
    } finally {
        verifyBtn.disabled = false;
        verifyBtn.innerHTML = originalText;
    }
}

function displayVerificationResult(result) {
    const resultContainer = document.querySelector('#verificationResult');
    if (!resultContainer) return;
    
    const html = `
        <div class="alert alert-success">
            <h4><i class="fas fa-check-circle me-2"></i>Receipt Verified!</h4>
            <hr>
            <p><strong>Voted at:</strong> ${new Date(result.timestamp).toLocaleString()}</p>
            <p><strong>Signature Status:</strong> 
                <span class="badge bg-success">Valid</span>
            </p>
            <p><strong>Vote Status:</strong> 
                <span class="badge bg-info">Counted</span>
            </p>
            <p class="mb-0 text-muted small">
                Your vote has been securely recorded and will be included in the final tally.
            </p>
        </div>
    `;
    
    resultContainer.innerHTML = html;
    resultContainer.classList.remove('d-none');
}

function copyReceiptCode() {
    const receiptCode = document.querySelector('.receipt-code').textContent;
    
    navigator.clipboard.writeText(receiptCode).then(() => {
        const btn = document.querySelector('#copyReceiptCode');
        const originalText = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-check me-2"></i>Copied!';
        
        setTimeout(() => {
            btn.innerHTML = originalText;
        }, 2000);
        
        showAlert('Receipt code copied to clipboard', 'success');
    }).catch(err => {
        console.error('Copy failed:', err);
        showAlert('Failed to copy receipt code', 'danger');
    });
}

function downloadReceipt() {
    // Create a downloadable text file with receipt info
    const receiptCode = document.querySelector('.receipt-code').textContent;
    const timestamp = document.querySelector('.receipt-timestamp')?.textContent || new Date().toISOString();
    
    const receiptText = `
QUANTUM-SAFE E-VOTING SYSTEM
VOTE RECEIPT
==================================================

Receipt Code: ${receiptCode}
Timestamp: ${timestamp}

This receipt confirms that your vote has been 
securely recorded using quantum-safe cryptography.

Your vote is:
✓ Encrypted with Kyber-512
✓ Signed with Dilithium-2  
✓ Anonymous and verifiable
✓ Tamper-proof

Save this receipt to verify your vote was counted.

To verify: https://vote.example.com/verify/${receiptCode}

==================================================
© 2024 QuantumVote - Built for a quantum-safe future
    `.trim();
    
    // Create blob and download
    const blob = new Blob([receiptText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vote-receipt-${receiptCode}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showAlert('Receipt downloaded successfully', 'success');
}

// =============================================================================
// ADMIN PANEL
// =============================================================================

function initializeAdminPanel() {
    // Refresh results button
    const refreshBtn = document.querySelector('#refreshResults');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadResults);
    }
    
    // Export results button
    const exportBtn = document.querySelector('#exportResults');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportResults);
    }
    
    // Decrypt votes button
    const decryptBtn = document.querySelector('#decryptVotes');
    if (decryptBtn) {
        decryptBtn.addEventListener('click', decryptVotes);
    }
    
    // Auto-refresh results every 30 seconds
    if (document.querySelector('#resultsChart')) {
        setInterval(loadResults, 30000);
    }
}

async function loadResults() {
    try {
        const response = await fetch('/admin/results');
        if (response.ok) {
            const results = await response.json();
            updateResultsChart(results);
            updateResultsTable(results);
        }
    } catch (error) {
        console.error('Failed to load results:', error);
    }
}

function updateResultsChart(results) {
    const chartCanvas = document.querySelector('#resultsChart');
    if (!chartCanvas) return;
    
    // Prepare data for Chart.js
    const labels = results.map(r => r.candidate_name);
    const votes = results.map(r => r.votes);
    const colors = generateColors(results.length);
    
    // Create or update chart
    if (window.resultsChart) {
        window.resultsChart.data.labels = labels;
        window.resultsChart.data.datasets[0].data = votes;
        window.resultsChart.update();
    } else {
        const ctx = chartCanvas.getContext('2d');
        window.resultsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Votes',
                    data: votes,
                    backgroundColor: colors,
                    borderColor: colors.map(c => c.replace('0.6', '1')),
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'Real-Time Voting Results',
                        font: {
                            size: 18,
                            weight: 'bold'
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    }
}

function updateResultsTable(results) {
    const tableBody = document.querySelector('#resultsTableBody');
    if (!tableBody) return;
    
    const totalVotes = results.reduce((sum, r) => sum + r.votes, 0);
    
    const html = results.map((result, index) => {
        const percentage = totalVotes > 0 ? ((result.votes / totalVotes) * 100).toFixed(1) : 0;
        return `
            <tr>
                <td>${index + 1}</td>
                <td><strong>${result.candidate_name}</strong></td>
                <td>${result.party}</td>
                <td><span class="badge bg-primary">${result.votes}</span></td>
                <td>
                    <div class="progress" style="height: 25px;">
                        <div class="progress-bar bg-success" 
                             role="progressbar" 
                             style="width: ${percentage}%"
                             aria-valuenow="${percentage}" 
                             aria-valuemin="0" 
                             aria-valuemax="100">
                            ${percentage}%
                        </div>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
    
    tableBody.innerHTML = html;
    
    // Update total votes display
    const totalVotesElement = document.querySelector('#totalVotes');
    if (totalVotesElement) {
        totalVotesElement.textContent = totalVotes;
    }
}

async function exportResults() {
    try {
        const response = await fetch('/admin/export_results');
        if (response.ok) {
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `voting-results-${new Date().toISOString()}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            showAlert('Results exported successfully', 'success');
        }
    } catch (error) {
        console.error('Export failed:', error);
        showAlert('Failed to export results', 'danger');
    }
}

async function decryptVotes() {
    const confirmed = confirm(
        'Are you sure you want to decrypt all votes? ' +
        'This action is irreversible and should only be done after voting ends.'
    );
    
    if (!confirmed) return;
    
    const decryptBtn = document.querySelector('#decryptVotes');
    const originalText = decryptBtn.innerHTML;
    decryptBtn.disabled = true;
    decryptBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Decrypting...';
    
    try {
        const response = await fetch('/admin/decrypt_votes', {
            method: 'POST'
        });
        
        if (response.ok) {
            const result = await response.json();
            showAlert(`Successfully decrypted ${result.count} votes`, 'success');
            loadResults(); // Refresh results
        } else {
            showAlert('Failed to decrypt votes', 'danger');
        }
    } catch (error) {
        console.error('Decryption error:', error);
        showAlert('An error occurred during decryption', 'danger');
    } finally {
        decryptBtn.disabled = false;
        decryptBtn.innerHTML = originalText;
    }
}

// =============================================================================
// ANIMATIONS AND UI ENHANCEMENTS
// =============================================================================

function initializeAnimations() {
    // Fade in elements on scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-fade-in');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);
    
    // Observe all cards and sections
    document.querySelectorAll('.card, .feature-box, .candidate-card').forEach(el => {
        observer.observe(el);
    });
    
    // Particle background effect (optional)
    createParticleBackground();
}

function createParticleBackground() {
    const particleContainer = document.querySelector('.particle-background');
    if (!particleContainer) return;
    
    // Create 50 particles
    for (let i = 0; i < 50; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 10 + 's';
        particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
        particleContainer.appendChild(particle);
    }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

function showAlert(message, type = 'info') {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 start-50 translate-middle-x mt-3`;
    alertDiv.style.zIndex = '9999';
    alertDiv.style.minWidth = '300px';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Add to page
    document.body.appendChild(alertDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        alertDiv.classList.remove('show');
        setTimeout(() => alertDiv.remove(), 150);
    }, 5000);
}

function generateColors(count) {
    const colors = [];
    const hueStep = 360 / count;
    
    for (let i = 0; i < count; i++) {
        const hue = i * hueStep;
        colors.push(`hsla(${hue}, 70%, 60%, 0.6)`);
    }
    
    return colors;
}

// =============================================================================
// ERROR HANDLING
// =============================================================================

window.addEventListener('error', function(e) {
    console.error('Global error:', e.error);
    // Don't show alert for every error, only critical ones
});

// Handle unhandled promise rejections
window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled promise rejection:', e.reason);
});

// =============================================================================
// END OF SCRIPT
// =============================================================================

console.log('✅ All frontend functionality loaded successfully');
