const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const archiver = require('archiver');
const XLSX = require('xlsx');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: '*',  // Allow all origins for testing
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(__dirname));

// Configure multer for file upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = 'uploads/resumes';
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        // Create a safe filename from original file name initially
        let safeName = 'resume';
        
        // If we have the student's name in the field, use it
        if (req.body && req.body.fullName) {
            safeName = req.body.fullName.replace(/[^a-zA-Z0-9]/g, '_');
        }
        
        const uniqueSuffix = Date.now();
        const finalName = `${safeName}-${uniqueSuffix}${path.extname(file.originalname)}`;
        
        // Store the filename temporarily so we can access it in the route
        req.resumeFileName = finalName;
        
        cb(null, finalName);
    }
});

const upload = multer({
    storage: storage,
    fileFilter: function (req, file, cb) {
        if (file.mimetype !== 'application/pdf') {
            return cb(new Error('Only PDF files are allowed'));
        }
        cb(null, true);
    },
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// MySQL Connection
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'security',
    database: 'resume_portal',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test database connection
db.getConnection((err, connection) => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('Database connected successfully');
    connection.release();
});

// Create admin user with hashed password
async function createAdminUser() {
    try {
        const hashedPassword = await bcrypt.hash('Stab@123', 10);
        await db.promise().query(
            'UPDATE users SET password_hash = ? WHERE email = ?',
            [hashedPassword, 'team@stabforge.com']
        );
        console.log('Admin user password updated');
    } catch (error) {
        console.error('Error updating admin password:', error);
    }
}

// Call createAdminUser when server starts
createAdminUser();

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        req.userRole = decoded.role;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Middleware to check admin role
const requireAdmin = (req, res, next) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
    }
    next();
};

// Register endpoint (for students only)
app.post('/api/register', async (req, res) => {
    const { fullName, email, password } = req.body;
    
    if (!fullName || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    try {
        const [existingUser] = await db.promise().query('SELECT id FROM users WHERE email = ?', [email]);
        
        if (existingUser.length > 0) {
                return res.status(400).json({ error: 'Email already registered' });
            }
            
                const hashedPassword = await bcrypt.hash(password, 10);
        
        const [result] = await db.promise().query(
            'INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, ?)',
            [fullName, email, hashedPassword, 'student']
        );

        const token = jwt.sign({ userId: result.insertId, role: 'student' }, JWT_SECRET);
                    res.status(201).json({ token, message: 'Registration successful' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    console.log('Login attempt received:', req.body.email);
    const { email, password } = req.body;
    
    if (!email || !password) {
        console.log('Missing email or password');
        return res.status(400).json({ error: 'Email and password are required' });
    }
    
    try {
        const [users] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
        console.log('User found:', users.length > 0);

        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
            
        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        console.log('Password valid:', validPassword);
            
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
            
        const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET);
        console.log('Login successful for:', email);
        
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                fullName: user.full_name,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Submit profile and resume
app.post('/api/submit', verifyToken, (req, res, next) => {
    upload.single('resume')(req, res, async (err) => {
        if (err) {
            return res.status(400).json({ error: err.message });
        }

        try {
            const { fullName, mobile, email, institution, bio } = req.body;
            const userId = req.userId;
            const resumeFile = req.file;

            if (!resumeFile) {
                return res.status(400).json({ error: 'Resume file is required' });
            }

            // Rename the file with the student's name
            const oldPath = resumeFile.path;
            const newFileName = `${fullName.replace(/[^a-zA-Z0-9]/g, '_')}-${Date.now()}${path.extname(resumeFile.originalname)}`;
            const newPath = path.join('uploads/resumes', newFileName);

            fs.renameSync(oldPath, newPath);

            const [result] = await db.promise().query(
                `INSERT INTO submissions 
                (user_id, full_name, mobile_number, email, institution, bio, resume_filename, resume_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [userId, fullName, mobile, email, institution, bio, resumeFile.originalname, newPath]
            );

            res.json({ 
                success: true, 
                message: 'Submission successful',
                submissionId: result.insertId
            });
        } catch (error) {
            console.error('Submission error:', error);
            res.status(500).json({ error: 'Failed to submit profile' });
        }
    });
});

// Get user's submission
app.get('/api/submission', verifyToken, async (req, res) => {
    try {
        const [submissions] = await db.promise().query(
            'SELECT * FROM submissions WHERE user_id = ? ORDER BY submission_date DESC LIMIT 1',
            [req.userId]
        );

        if (submissions.length === 0) {
            return res.json({ 
                success: true,
                submission: null
            });
        }

        res.json({
            success: true,
            submission: submissions[0]
        });
    } catch (error) {
        console.error('Error fetching submission:', error);
        res.status(500).json({ error: 'Failed to fetch submission' });
    }
});

// Admin: Get all submissions
app.get('/api/admin/submissions', verifyToken, requireAdmin, async (req, res) => {
    try {
        const [submissions] = await db.promise().query(
            `SELECT s.*, u.email as user_email 
             FROM submissions s 
             JOIN users u ON s.user_id = u.id 
             ORDER BY s.submission_date DESC`
        );

        res.json({
            success: true,
            submissions: submissions
        });
    } catch (error) {
        console.error('Error fetching submissions:', error);
        res.status(500).json({ error: 'Failed to fetch submissions' });
    }
});

// Admin: Download all resumes
app.get('/api/admin/download-all', async (req, res) => {
    try {
        const token = req.query.token;
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.role !== 'admin') {
                return res.status(403).json({ error: 'Access denied' });
            }
        } catch (error) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        const [submissions] = await db.promise().query('SELECT * FROM submissions');
        
        const archive = archiver('zip', {
            zlib: { level: 9 }
        });

        res.attachment('all-resumes.zip');
        archive.pipe(res);

        for (const submission of submissions) {
            if (submission.resume_path && fs.existsSync(submission.resume_path)) {
                archive.file(submission.resume_path, { 
                    name: `${submission.full_name}-${submission.id}.pdf`
                });
            }
        }

        await archive.finalize();
    } catch (error) {
        console.error('Error creating zip:', error);
        res.status(500).json({ error: 'Failed to create zip file' });
    }
});

// Download single resume
app.get('/api/resume/:submissionId', async (req, res) => {
    try {
        const token = req.query.token;
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
        } catch (error) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        const [submissions] = await db.promise().query(
            'SELECT * FROM submissions WHERE id = ?',
            [req.params.submissionId]
        );

        if (submissions.length === 0 || !submissions[0].resume_path) {
            return res.status(404).json({ error: 'Resume not found' });
        }

        const submission = submissions[0];

        // Check if user is admin or the owner of the submission
        if (decoded.role !== 'admin' && decoded.userId !== submission.user_id) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Update is_downloaded status if admin is downloading
        if (decoded.role === 'admin') {
            await db.promise().query(
                'UPDATE submissions SET is_downloaded = TRUE WHERE id = ?',
                [req.params.submissionId]
            );
        }

        // Set proper headers for file download
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${submission.resume_filename}"`);
        
        // Send the file
        res.sendFile(path.resolve(submission.resume_path), (err) => {
            if (err) {
                console.error('Download error:', err);
                return res.status(500).json({ error: 'Error downloading file' });
            }
        });
    } catch (error) {
        console.error('Resume download error:', error);
        res.status(500).json({ error: 'Failed to download resume' });
    }
});

// View single resume
app.get('/api/resume/view/:submissionId', async (req, res) => {
    console.log('View resume endpoint hit:', req.params.submissionId);
    try {
        // Get token from query parameter
        const token = req.query.token;
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        // Verify token
        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
        } catch (error) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        const [submissions] = await db.promise().query(
            'SELECT * FROM submissions WHERE id = ?',
            [req.params.submissionId]
        );

        if (submissions.length === 0 || !submissions[0].resume_path) {
            console.log('Resume not found in database');
            return res.status(404).json({ error: 'Resume not found' });
        }

        const submission = submissions[0];

        // Check if user is admin or the owner of the submission
        if (decoded.role !== 'admin' && decoded.userId !== submission.user_id) {
            return res.status(403).json({ error: 'Access denied' });
        }

        console.log('Resume path:', submission.resume_path);

        // Check if file exists
        if (!fs.existsSync(submission.resume_path)) {
            console.log('Resume file not found on disk');
            return res.status(404).json({ error: 'Resume file not found' });
        }

        // Set proper headers for PDF viewing in browser
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'inline; filename="' + submission.resume_filename + '"');
        
        // Send the file
        const absolutePath = path.resolve(submission.resume_path);
        console.log('Sending file from:', absolutePath);
        
        res.sendFile(absolutePath, (err) => {
            if (err) {
                console.error('View error:', err);
                return res.status(500).json({ error: 'Error viewing file' });
            }
        });
    } catch (error) {
        console.error('Resume view error:', error);
        res.status(500).json({ error: 'Failed to view resume' });
    }
});

// Admin: Delete submission
app.delete('/api/admin/submission/:submissionId', verifyToken, requireAdmin, async (req, res) => {
    try {
        // Get submission details first to get the file path
        const [submissions] = await db.promise().query(
            'SELECT * FROM submissions WHERE id = ?',
            [req.params.submissionId]
        );

        if (submissions.length === 0) {
            return res.status(404).json({ error: 'Submission not found' });
        }

        const submission = submissions[0];

        // Delete the file if it exists
        if (submission.resume_path && fs.existsSync(submission.resume_path)) {
            fs.unlinkSync(submission.resume_path);
        }

        // Delete from database
        await db.promise().query(
            'DELETE FROM submissions WHERE id = ?',
            [req.params.submissionId]
        );

        res.json({ success: true, message: 'Submission deleted successfully' });
    } catch (error) {
        console.error('Delete submission error:', error);
        res.status(500).json({ error: 'Failed to delete submission' });
    }
});

// Admin: Update submission qualification status
app.put('/api/admin/submission/:submissionId/status', verifyToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const validStatuses = ['pending', 'qualified', 'disqualified'];
        
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status value' });
        }

        await db.promise().query(
            'UPDATE submissions SET qualification_status = ? WHERE id = ?',
            [status, req.params.submissionId]
        );

        res.json({ success: true, message: 'Status updated successfully' });
    } catch (error) {
        console.error('Update status error:', error);
        res.status(500).json({ error: 'Failed to update status' });
    }
});

// Admin: Download all records in Excel
app.get('/api/admin/download-records', verifyToken, requireAdmin, async (req, res) => {
    try {
        // Fetch all submissions
        const [submissions] = await db.promise().query(
            `SELECT full_name, email, mobile_number, institution, 
             DATE_FORMAT(submission_date, '%Y-%m-%d %H:%i:%s') as submission_date,
             qualification_status
             FROM submissions 
             ORDER BY submission_date DESC`
        );

        // Create workbook and worksheet
        const workbook = XLSX.utils.book_new();
        const worksheet = XLSX.utils.json_to_sheet(submissions);

        // Set column widths
        const columnWidths = [
            { wch: 20 }, // full_name
            { wch: 25 }, // email
            { wch: 15 }, // mobile_number
            { wch: 30 }, // institution
            { wch: 20 }, // submission_date
            { wch: 15 }  // qualification_status
        ];
        worksheet['!cols'] = columnWidths;

        // Add the worksheet to the workbook
        XLSX.utils.book_append_sheet(workbook, worksheet, 'Submissions');

        // Generate buffer
        const excelBuffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });

        // Set headers for file download
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=submissions.xlsx');
        
        // Send the file
        res.send(excelBuffer);

    } catch (error) {
        console.error('Error generating Excel:', error);
        res.status(500).json({ error: 'Failed to generate Excel file' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
}); 