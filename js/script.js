// Check if user is logged in and redirect based on role
function checkAuth() {
    const token = localStorage.getItem('token');
    const userRole = localStorage.getItem('userRole');
    const currentPage = window.location.pathname;

    if (!token) {
        if (!currentPage.includes('index.html') && !currentPage.includes('signup.html')) {
            window.location.href = 'index.html';
        }
        return;
    }

    // Redirect based on role
    if (userRole === 'admin') {
        if (currentPage.includes('dashboard.html')) {
            window.location.href = 'admin.html';
        }
    } else {
        if (currentPage.includes('admin.html')) {
            window.location.href = 'dashboard.html';
        }
    }
}

// Handle login form submission
async function handleLogin(event) {
    event.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const spinner = document.getElementById('loginSpinner');
    
    try {
        spinner.style.display = 'inline-block';
        console.log('Attempting login...');
        
        const response = await fetch('http://localhost:3000/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        
        console.log('Response status:', response.status);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Login failed');
        }
        
        console.log('Login successful');
        localStorage.setItem('token', data.token);
        localStorage.setItem('userRole', data.user.role);
        localStorage.setItem('userName', data.user.fullName);
        
        // Redirect based on role
        if (data.user.role === 'admin') {
            window.location.href = 'admin.html';
        } else {
            window.location.href = 'dashboard.html';
        }
    } catch (error) {
        console.error('Login error:', error);
        alert(error.message || 'Failed to connect to server. Please make sure the server is running.');
    } finally {
        spinner.style.display = 'none';
    }
}

// Handle signup form submission
async function handleSignup(event) {
    event.preventDefault();
    
    const fullName = document.getElementById('fullName').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const spinner = document.getElementById('signupSpinner');
    
    if (password !== confirmPassword) {
        alert('Passwords do not match');
        return;
    }
    
    try {
        spinner.style.display = 'inline-block';
        
        const response = await fetch('http://localhost:3000/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ fullName, email, password })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Registration failed');
        }
        
        alert('Registration successful! Please login.');
        window.location.href = 'index.html';
    } catch (error) {
        alert(error.message);
    } finally {
        spinner.style.display = 'none';
    }
}

// Handle profile form submission
async function handleProfileSubmit(event) {
    event.preventDefault();
    
    const fullName = document.getElementById('fullName').value;
    const mobile = document.getElementById('mobile').value;
    const email = document.getElementById('email').value;
    const institution = document.getElementById('institution').value;
    const bio = document.getElementById('bio').value;
    const resumeFile = document.getElementById('resumeFile').files[0];
    const spinner = document.getElementById('submitSpinner');
    
    const formData = new FormData();
    formData.append('fullName', fullName);
    formData.append('mobile', mobile);
    formData.append('email', email);
    formData.append('institution', institution);
    formData.append('bio', bio);
    if (resumeFile) {
        formData.append('resume', resumeFile);
    }
    
    try {
        spinner.style.display = 'inline-block';
        
        const response = await fetch('http://localhost:3000/api/submit', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: formData
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to submit profile');
        }
        
        alert('Profile submitted successfully');
        loadSubmission();
    } catch (error) {
        alert(error.message);
    } finally {
        spinner.style.display = 'none';
    }
}

// Load user's submission
async function loadSubmission() {
    try {
        const response = await fetch('http://localhost:3000/api/submission', {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to fetch submission');
        }
        
        if (data.submission) {
            document.getElementById('fullName').value = data.submission.full_name;
            document.getElementById('mobile').value = data.submission.mobile_number;
            document.getElementById('email').value = data.submission.email;
            document.getElementById('institution').value = data.submission.institution;
            document.getElementById('bio').value = data.submission.bio;
            
            // Display current resume if exists
            const currentResumeDiv = document.getElementById('currentResume');
            if (data.submission.resume_filename) {
                const token = localStorage.getItem('token');
                currentResumeDiv.innerHTML = `
                    <p>Current Resume: ${data.submission.resume_filename}</p>
                    <a href="http://localhost:3000/api/resume/${data.submission.id}" 
                       class="btn btn-sm btn-primary"
                       onclick="downloadResume(event, ${data.submission.id})">
                        <i class="fas fa-download"></i> Download
                    </a>
                `;
            } else {
                currentResumeDiv.innerHTML = '<p>No resume uploaded yet</p>';
            }
        }
    } catch (error) {
        console.error('Error loading submission:', error);
    }
}

// Handle submission deletion
async function deleteSubmission(submissionId) {
    if (!confirm('Are you sure you want to delete this submission? This action cannot be undone.')) {
        return;
    }

    try {
        const response = await fetch(`http://localhost:3000/api/admin/submission/${submissionId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to delete submission');
        }

        // Refresh the submissions table
        loadAllSubmissions();
        alert('Submission deleted successfully');
    } catch (error) {
        console.error('Error deleting submission:', error);
        alert(error.message);
    }
}

// Handle qualification status change
async function updateQualificationStatus(submissionId, status) {
    try {
        const response = await fetch(`http://localhost:3000/api/admin/submission/${submissionId}/status`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ status })
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to update status');
        }

        // Refresh the submissions table
        loadAllSubmissions();
    } catch (error) {
        console.error('Error updating status:', error);
        alert(error.message);
    }
}

// View resume in modal
async function viewResume(submissionId) {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            alert('Please login again');
            return;
        }

        const pdfViewer = document.getElementById('pdfViewer');
        // Set the iframe source with authorization token in URL
        pdfViewer.src = `http://localhost:3000/api/resume/view/${submissionId}?token=${encodeURIComponent(token)}`;
        
        // Show the modal
        const modal = new bootstrap.Modal(document.getElementById('pdfViewerModal'));
        modal.show();
    } catch (error) {
        console.error('Error viewing resume:', error);
        alert('Failed to view resume: ' + error.message);
    }
}

// Load all submissions for admin
async function loadAllSubmissions() {
    try {
        const response = await fetch('http://localhost:3000/api/admin/submissions', {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to fetch submissions');
        }
        
        const submissionsTable = document.getElementById('submissionsTable');
        const tbody = submissionsTable.querySelector('tbody');
        tbody.innerHTML = '';
        
        data.submissions.forEach(submission => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${submission.full_name}</td>
                <td>${submission.email}</td>
                <td>${submission.mobile_number}</td>
                <td>${submission.institution}</td>
                <td>${new Date(submission.submission_date).toLocaleString()}</td>
                <td>
                    <div class="form-check">
                        <input type="checkbox" class="form-check-input" 
                               ${submission.is_downloaded ? 'checked' : ''} 
                               disabled>
                    </div>
                </td>
                <td>
                    <select class="form-select form-select-sm" 
                            onchange="updateQualificationStatus(${submission.id}, this.value)">
                        <option value="pending" ${submission.qualification_status === 'pending' ? 'selected' : ''}>Pending</option>
                        <option value="qualified" ${submission.qualification_status === 'qualified' ? 'selected' : ''}>Qualified</option>
                        <option value="disqualified" ${submission.qualification_status === 'disqualified' ? 'selected' : ''}>Disqualified</option>
                    </select>
                </td>
                <td>
                    <div class="btn-group" role="group">
                        <button class="btn btn-sm btn-info" 
                                onclick="viewResume(${submission.id})">
                            <i class="fas fa-eye"></i> View
                        </button>
                        <a href="http://localhost:3000/api/resume/${submission.id}?token=${localStorage.getItem('token')}" 
                           class="btn btn-sm btn-primary ms-2"
                           onclick="downloadResume(event, ${submission.id})">
                            <i class="fas fa-download"></i> Download
                        </a>
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });
    } catch (error) {
        console.error('Error loading submissions:', error);
        alert('Failed to load submissions');
    }
}

// Handle resume download
async function downloadResume(event, submissionId) {
    event.preventDefault();
    const token = localStorage.getItem('token');
    
    try {
        window.location.href = `http://localhost:3000/api/resume/${submissionId}?token=${token}`;
    } catch (error) {
        console.error('Error downloading resume:', error);
        alert('Failed to download resume');
    }
}

// Download all resumes as zip
async function downloadAllResumes() {
    try {
        const token = localStorage.getItem('token');
        window.location.href = `http://localhost:3000/api/admin/download-all?token=${token}`;
    } catch (error) {
        console.error('Error downloading resumes:', error);
        alert('Failed to download resumes');
    }
}

// Download all records as Excel
async function downloadAllRecords() {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            alert('Please login again');
            return;
        }

        const response = await fetch('http://localhost:3000/api/admin/download-records', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to download records');
        }

        // Get the blob from the response
        const blob = await response.blob();
        
        // Create a download link and trigger it
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'submissions.xlsx';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } catch (error) {
        console.error('Error downloading records:', error);
        alert('Failed to download records: ' + error.message);
    }
}

// Handle logout
function handleLogout() {
    localStorage.removeItem('token');
    localStorage.removeItem('userRole');
    localStorage.removeItem('userName');
    window.location.href = 'index.html';
}

// Initialize page
function initializePage() {
    checkAuth();
    
    const userNameElement = document.getElementById('userName');
    if (userNameElement) {
        userNameElement.textContent = localStorage.getItem('userName');
    }
    
    // Load appropriate content based on page
    if (window.location.pathname.includes('admin.html')) {
        loadAllSubmissions();
    } else if (window.location.pathname.includes('dashboard.html')) {
        loadSubmission();
    }
}

// Call initialize function when page loads
document.addEventListener('DOMContentLoaded', initializePage);

// PDF zoom functionality
let currentZoom = 1;
const ZOOM_STEP = 0.25;
const MIN_ZOOM = 0.5;
const MAX_ZOOM = 3;

function zoomPDF(action) {
    const iframe = document.getElementById('pdfViewer');
    
    switch(action) {
        case 'in':
            if (currentZoom < MAX_ZOOM) {
                currentZoom += ZOOM_STEP;
            }
            break;
        case 'out':
            if (currentZoom > MIN_ZOOM) {
                currentZoom -= ZOOM_STEP;
            }
            break;
        case 'reset':
            currentZoom = 1;
            break;
    }
    
    iframe.style.transform = `scale(${currentZoom})`;
    
    // Adjust container width to accommodate zoom
    const container = iframe.parentElement;
    container.style.width = currentZoom === 1 ? '100%' : `${100 * currentZoom}%`;
}

// Reset zoom when modal is closed
document.getElementById('pdfViewerModal').addEventListener('hidden.bs.modal', function () {
    currentZoom = 1;
    const iframe = document.getElementById('pdfViewer');
    iframe.style.transform = 'scale(1)';
    iframe.parentElement.style.width = '100%';
}); 