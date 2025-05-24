-- Create the database
CREATE DATABASE IF NOT EXISTS resume_portal;
USE resume_portal;

-- Drop tables if they exist to avoid conflicts
DROP TABLE IF EXISTS submissions;
DROP TABLE IF EXISTS users;

-- Create users table with role
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'student') NOT NULL DEFAULT 'student',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_email (email)
);

-- Create submissions table
CREATE TABLE IF NOT EXISTS submissions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    mobile_number VARCHAR(20) NOT NULL,
    email VARCHAR(100) NOT NULL,
    institution VARCHAR(200) NOT NULL,
    bio TEXT NOT NULL,
    resume_filename VARCHAR(255),
    resume_path VARCHAR(255),
    is_downloaded BOOLEAN DEFAULT FALSE,
    qualification_status ENUM('pending', 'qualified', 'disqualified') DEFAULT 'pending',
    submission_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_user_role ON users(role);
CREATE INDEX idx_submissions_user ON submissions(user_id);

-- Insert admin user
INSERT INTO users (full_name, email, password_hash, role) 
VALUES (
    'Admin',
    'team@stabforge.com',
    '$2a$10$YourHashedPasswordHere',  -- Will update this in server.js
    'admin'
); 

-- Add is_downloaded column to submissions table
ALTER TABLE submissions
ADD COLUMN is_downloaded BOOLEAN DEFAULT FALSE; 

DESCRIBE submissions; 