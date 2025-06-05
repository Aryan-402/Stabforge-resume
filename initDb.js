const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./models/User');
const Submission = require('./models/Submission');

async function initializeDatabase() {
    try {
        // Connect to MongoDB
        await mongoose.connect('mongodb://localhost:27017/resume_portal', {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log('Connected to MongoDB');

        // Drop existing collections if they exist
        await mongoose.connection.db.dropDatabase();
        console.log('Dropped existing database');

        // Create admin user with proper password hashing
        const adminUser = new User({
            fullName: 'Admin',
            email: 'team@stabforge.com',
            passwordHash: 'Stab@123', // This will be hashed by the pre-save middleware
            role: 'admin'
        });
        await adminUser.save();
        console.log('Created admin user:', adminUser.email);

        // Create test student user with proper password hashing
        const studentUser = new User({
            fullName: 'Test Student',
            email: 'student@test.com',
            passwordHash: 'student123', // This will be hashed by the pre-save middleware
            role: 'student'
        });
        await studentUser.save();
        console.log('Created test student user:', studentUser.email);

        // Create test submission
        const testSubmission = await Submission.create({
            userId: studentUser._id,
            fullName: 'Test Student',
            mobileNumber: '1234567890',
            email: 'student@test.com',
            institution: 'Test University',
            bio: 'Test bio for demonstration',
            resumeFilename: 'test-resume.pdf',
            resumePath: 'uploads/resumes/test-resume.pdf',
            qualificationStatus: 'pending'
        });
        console.log('Created test submission');

        console.log('\nDatabase initialization completed successfully!');
        console.log('\nAdmin login credentials:');
        console.log('Email: team@stabforge.com');
        console.log('Password: Stab@123');
        console.log('\nTest student credentials:');
        console.log('Email: student@test.com');
        console.log('Password: student123');

        await mongoose.connection.close();
        console.log('\nDatabase connection closed');
        
    } catch (error) {
        console.error('Error initializing database:', error);
        process.exit(1);
    }
}

initializeDatabase(); 