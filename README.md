# Resume Management System

A role-based web application for managing student resumes with admin capabilities.

## Features

- Role-based access (Admin and Student)
- Student Features:
  - Profile management
  - Resume upload (PDF format, max 5MB)
  - Personal information management
- Admin Features:
  - View all student profiles
  - Download consolidated data in Excel format
  - Manage user accounts

## Technical Stack

- Frontend: HTML, CSS, JavaScript, Bootstrap
- Backend: Java (Spring Boot)
- Database: MySQL
- Authentication: Spring Security

## Setup Instructions

1. Database Setup:
   ```sql
   CREATE DATABASE resume_db;
   ```

2. Configure application.properties:
   - Update database credentials
   - Configure file upload settings

3. Build and Run:
   ```bash
   mvn clean install
   java -jar target/resume-management-system.jar
   ```

4. Access the application:
   - URL: http://localhost:8080
   - Default admin credentials:
     - Email: admin@system.com
     - Password: admin123

## Deployment Notes

- Configured for Hostinger deployment
- Make sure to update the application.properties for production
- Set up proper SSL certificates
- Configure proper file upload limits in production 