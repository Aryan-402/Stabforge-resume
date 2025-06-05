const mongoose = require('mongoose');

const submissionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    fullName: {
        type: String,
        required: true
    },
    mobileNumber: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    institution: {
        type: String,
        required: true
    },
    bio: {
        type: String,
        required: true
    },
    resumeFilename: {
        type: String
    },
    resumePath: {
        type: String
    },
    isDownloaded: {
        type: Boolean,
        default: false
    },
    qualificationStatus: {
        type: String,
        enum: ['pending', 'qualified', 'disqualified'],
        default: 'pending'
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('Submission', submissionSchema); 