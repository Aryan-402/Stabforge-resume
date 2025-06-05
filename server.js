const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const archiver = require('archiver');
const XLSX = require('xlsx');
require('dotenv').config();

// Import models
const User = require('./models/User');
const Submission = require('./models/Submission');

const app = express();

// Middleware
app.use(cors({
    origin: '*',
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
        let safeName = 'resume';
        
        if (req.body && req.body.fullName) {
            safeName = req.body.fullName.replace(/[^a-zA-Z0-9]/g, '_');
        }
        
        const uniqueSuffix = Date.now();
        const finalName = `${safeName}-${uniqueSuffix}${path.extname(file.originalname)}`;
        
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

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/resume_portal', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {
    console.log('MongoDB connected successfully');
    createAdminUser();
})
.catch(err => {
    console.error('MongoDB connection error:', err);
});

// Create admin user
async function createAdminUser() {
    try {
        const adminEmail = 'team@stabforge.com';
        const adminPassword = 'Stab@123';

        const existingAdmin = await User.findOne({ email: adminEmail });
        if (!existingAdmin) {
            const adminUser = new User({
                fullName: 'Admin',
                email: adminEmail,
                passwordHash: adminPassword,
                role: 'admin'
            });
            await adminUser.save();
            console.log('Admin user created successfully');
        }
    } catch (error) {
        console.error('Error creating admin user:', error);
    }
}

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
        const existingUser = await User.findOne({ email });
        
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        const user = await User.create({
            fullName,
            email,
            passwordHash: password,
            role: 'student'
        });

        const token = jwt.sign({ userId: user._id, role: 'student' }, JWT_SECRET);
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
        const user = await User.findOne({ email });
        console.log('User found:', !!user);

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
            
        const validPassword = await user.comparePassword(password);
        console.log('Password valid:', validPassword);
            
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
            
        const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET);
        console.log('Login successful for:', email);
        
        // If user is a student, get their submission to get the full name
        let fullName = user.fullName;
        if (user.role === 'student') {
            const submission = await Submission.findOne({ userId: user._id });
            if (submission) {
                fullName = submission.fullName;
            }
        }
        
        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                fullName: fullName
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Submit resume endpoint
app.post('/api/submit', verifyToken, upload.single('resume'), async (req, res) => {
    try {
        // Check if user already has a submission
        let submission = await Submission.findOne({ userId: req.userId });
        
        // If old resume exists and new resume is uploaded, delete the old one
        if (submission && submission.resumePath && req.file) {
            try {
                const oldFilePath = path.join(__dirname, submission.resumePath);
                if (fs.existsSync(oldFilePath)) {
                    fs.unlinkSync(oldFilePath);
                    console.log(`Deleted old resume: ${submission.resumeFilename}`);
                }
            } catch (deleteError) {
                console.error('Error deleting old resume:', deleteError);
                // Continue with the update even if delete fails
            }
        }

        const updateData = {
            fullName: req.body.fullName,
            mobileNumber: req.body.mobile,
            email: req.body.email,
            institution: req.body.institution,
            bio: req.body.bio
        };

        // Only update resume data if a new file was uploaded
        if (req.file) {
            updateData.resumeFilename = req.resumeFileName;
            updateData.resumePath = `uploads/resumes/${req.resumeFileName}`;
        }

        if (submission) {
            // Update existing submission
            submission = await Submission.findOneAndUpdate(
                { userId: req.userId },
                updateData,
                { new: true }
            );
            res.json({
                message: 'Profile updated successfully',
                submission
            });
        } else {
            // Create new submission
            if (!req.file) {
                return res.status(400).json({ error: 'Resume file is required for initial submission' });
            }
            submission = await Submission.create({
                userId: req.userId,
                ...updateData,
                resumeFilename: req.resumeFileName,
                resumePath: `uploads/resumes/${req.resumeFileName}`
            });
            res.status(201).json({
                message: 'Profile submitted successfully',
                submission
            });
        }
    } catch (error) {
        console.error('Submission error:', error);
        res.status(500).json({ error: 'Error submitting profile' });
    }
});

// Get user's submission
app.get('/api/submission', verifyToken, async (req, res) => {
    try {
        const submission = await Submission.findOne({ userId: req.userId });
        res.json({ submission });
    } catch (error) {
        console.error('Error fetching submission:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get all submissions (admin only)
app.get('/api/submissions', verifyToken, requireAdmin, async (req, res) => {
    try {
        const submissions = await Submission.find().populate('userId', 'email');
        res.json(submissions);
    } catch (error) {
        console.error('Error fetching submissions:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update submission status (admin only)
app.put('/api/submissions/:id/status', verifyToken, requireAdmin, async (req, res) => {
    try {
        const submission = await Submission.findByIdAndUpdate(
            req.params.id,
            { qualificationStatus: req.body.status },
            { new: true }
        );
        
        if (!submission) {
            return res.status(404).json({ error: 'Submission not found' });
        }
        
        res.json({ success: true, submission });
    } catch (error) {
        console.error('Error updating submission status:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Mark resume as downloaded
app.put('/api/submissions/:id/downloaded', verifyToken, requireAdmin, async (req, res) => {
    try {
        const submission = await Submission.findByIdAndUpdate(
            req.params.id,
            { isDownloaded: true },
            { new: true }
        );
        
        if (!submission) {
            return res.status(404).json({ error: 'Submission not found' });
        }
        
        res.json({ success: true, submission });
    } catch (error) {
        console.error('Error marking resume as downloaded:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// View resume endpoint
app.get('/api/resume/view/:id', verifyToken, async (req, res) => {
    try {
        const submission = await Submission.findById(req.params.id);
        
        if (!submission) {
            return res.status(404).json({ error: 'Resume not found' });
        }

        // Check if user has permission to view this resume
        if (req.userRole !== 'admin' && submission.userId.toString() !== req.userId) {
            return res.status(403).json({ error: 'Access denied' });
        }

        const filePath = path.join(__dirname, submission.resumePath);
        
        if (fs.existsSync(filePath)) {
            // Set content type for PDF
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', 'inline; filename=' + submission.resumeFilename);
            res.sendFile(filePath);
        } else {
            res.status(404).json({ error: 'Resume file not found' });
        }
    } catch (error) {
        console.error('Error serving resume:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Download resume endpoint
app.get('/api/resume/:id', verifyToken, async (req, res) => {
    try {
        const submission = await Submission.findById(req.params.id);
        
        if (!submission) {
            return res.status(404).json({ error: 'Resume not found' });
        }

        // Check if user has permission to download this resume
        if (req.userRole !== 'admin' && submission.userId.toString() !== req.userId) {
            return res.status(403).json({ error: 'Access denied' });
        }

        const filePath = path.join(__dirname, submission.resumePath);
        
        if (fs.existsSync(filePath)) {
            // Update download status if admin is downloading
            if (req.userRole === 'admin') {
                submission.isDownloaded = true;
                await submission.save();
            }

            // Set headers for file download
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', 'attachment; filename=' + submission.resumeFilename);
            res.sendFile(filePath);
        } else {
            res.status(404).json({ error: 'Resume file not found' });
        }
    } catch (error) {
        console.error('Error downloading resume:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Download all resumes endpoint (admin only)
app.get('/api/download-all-resumes', verifyToken, requireAdmin, async (req, res) => {
    try {
        const submissions = await Submission.find();
        const archive = archiver('zip');
        
        archive.on('error', (err) => {
            res.status(500).json({ error: 'Error creating zip file' });
        });
        
        res.attachment('all-resumes.zip');
        archive.pipe(res);
        
        for (const submission of submissions) {
            const filePath = path.join(__dirname, submission.resumePath);
            if (fs.existsSync(filePath)) {
                archive.file(filePath, { name: `${submission.fullName}-resume.pdf` });
            }
        }
        
        await archive.finalize();
    } catch (error) {
        console.error('Error downloading all resumes:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Download records as Excel (admin only)
app.get('/api/download-records', verifyToken, requireAdmin, async (req, res) => {
    try {
        const submissions = await Submission.find().populate('userId', 'email');
        
        const workbook = XLSX.utils.book_new();
        const worksheet = XLSX.utils.json_to_sheet(submissions.map(s => ({
            'Full Name': s.fullName,
            'Email': s.email,
            'Mobile': s.mobileNumber,
            'Institution': s.institution,
            'Bio': s.bio,
            'Status': s.qualificationStatus,
            'Downloaded': s.isDownloaded ? 'Yes' : 'No',
            'Submission Date': new Date(s.createdAt).toLocaleString()
        })));
        
        XLSX.utils.book_append_sheet(workbook, worksheet, 'Submissions');
        
        const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
        
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=submissions.xlsx');
        res.send(buffer);
    } catch (error) {
        console.error('Error downloading records:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
}); 