// ==============================================
// SERVER.JS - LUCT MANAGEMENT SYSTEM API
// ==============================================

// Import required modules
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Initialize Express application
const app = express();

// Configure CORS for production and development
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://your-frontend-domain.railway.app'] // Replace with your actual frontend domain
    : 'http://localhost:3000',
  credentials: true
};
app.use(cors(corsOptions));

// Parse JSON request bodies
app.use(express.json());

// ==============================================
// DATABASE CONFIGURATION FOR RAILWAY
// ==============================================

// Use connection pool for better reliability
const db = mysql.createPool({
  host: process.env.MYSQLHOST || 'caboose.proxy.rlwy.net',
  user: process.env.MYSQLUSER || 'root',
  password: process.env.MYSQLPASSWORD || 'tDsWkUNqPDunUbFiwixSKMLiieNhNzcA',
  database: process.env.MYSQLDATABASE || 'railway',
  port: process.env.MYSQLPORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Debug: Show connection details
console.log('🔧 Attempting to connect to database:');
console.log('   Host:', process.env.MYSQLHOST || 'localhost');
console.log('   Database:', process.env.MYSQLDATABASE || 'luct_db');
console.log('   Port:', process.env.MYSQLPORT || 3306);

// Test connection and create tables
db.getConnection(async (err, connection) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
    console.log('💡 Connection details used:', {
      host: process.env.MYSQLHOST,
      database: process.env.MYSQLDATABASE,
      port: process.env.MYSQLPORT
    });
  } else {
    console.log('✅ Successfully connected to LUCT database on Railway');
    console.log('📊 Database:', process.env.MYSQLDATABASE);
    
    // Create tables if they don't exist
    await createTables(connection);
    connection.release(); // Release back to pool
  }
});

// Handle pool errors
db.on('error', (err) => {
  console.error('💥 Database pool error:', err);
  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    console.log('🔄 Connection lost, pool will handle reconnection automatically');
  }
});

// ==============================================
// TABLE CREATION FUNCTION
// ==============================================

async function createTables() {
  try {
    console.log('Checking and creating tables if they do not exist...');

    // Create faculties table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS faculties (
        id int(11) NOT NULL AUTO_INCREMENT,
        name varchar(255) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY name (name)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ faculties table checked/created');

    // Create users table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS users (
        id int(11) NOT NULL AUTO_INCREMENT,
        name varchar(255) NOT NULL,
        email varchar(255) NOT NULL,
        password varchar(255) NOT NULL,
        role enum('admin','pl','prl','lecturer','student') NOT NULL,
        faculty_id int(11) DEFAULT NULL,
        stream_id int(11) DEFAULT NULL,
        program_id int(11) DEFAULT NULL,
        profile_set tinyint(1) DEFAULT 0,
        student_id varchar(20) DEFAULT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY email (email),
        UNIQUE KEY student_id (student_id),
        KEY faculty_id (faculty_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ users table checked/created');

    // Create streams table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS streams (
        id int(11) NOT NULL AUTO_INCREMENT,
        name varchar(255) NOT NULL,
        faculty_id int(11) NOT NULL,
        prl_id int(11) DEFAULT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY stream_name_faculty (name,faculty_id),
        KEY faculty_id (faculty_id),
        KEY prl_id (prl_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ streams table checked/created');

    // Create programs table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS programs (
        id int(11) NOT NULL AUTO_INCREMENT,
        name varchar(255) NOT NULL,
        stream_id int(11) NOT NULL,
        pl_id int(11) DEFAULT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY program_name_stream (name,stream_id),
        KEY stream_id (stream_id),
        KEY pl_id (pl_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ programs table checked/created');

    // Create courses table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS courses (
        id int(11) NOT NULL AUTO_INCREMENT,
        name varchar(255) NOT NULL,
        code varchar(50) NOT NULL,
        program_id int(11) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY code (code),
        KEY program_id (program_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ courses table checked/created');

    // Create classes table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS classes (
        id int(11) NOT NULL AUTO_INCREMENT,
        name varchar(255) NOT NULL,
        course_id int(11) DEFAULT NULL,
        lecturer_id int(11) DEFAULT NULL,
        venue varchar(255) DEFAULT NULL,
        scheduled_time time DEFAULT NULL,
        total_students int(11) NOT NULL,
        semester varchar(50) DEFAULT NULL,
        academic_year varchar(20) DEFAULT NULL,
        active tinyint(1) DEFAULT 1,
        PRIMARY KEY (id),
        KEY course_id (course_id),
        KEY lecturer_id (lecturer_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ classes table checked/created');

    // Create students table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS students (
        id int(11) NOT NULL AUTO_INCREMENT,
        student_id varchar(20) NOT NULL,
        program_id int(11) DEFAULT NULL,
        created_at timestamp NOT NULL DEFAULT current_timestamp(),
        user_id int(11) DEFAULT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY student_id (student_id),
        UNIQUE KEY user_id (user_id),
        KEY program_id (program_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ students table checked/created');

    // Create attendance table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS attendance (
        id int(11) NOT NULL AUTO_INCREMENT,
        class_id int(11) NOT NULL,
        student_id int(11) NOT NULL,
        date date NOT NULL,
        present tinyint(1) DEFAULT 0,
        marked_by int(11) DEFAULT NULL,
        created_at timestamp NOT NULL DEFAULT current_timestamp(),
        PRIMARY KEY (id),
        UNIQUE KEY unique_attendance (class_id,student_id,date),
        KEY student_id (student_id),
        KEY marked_by (marked_by)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ attendance table checked/created');

    // Create class_students table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS class_students (
        id int(11) NOT NULL AUTO_INCREMENT,
        student_id int(11) NOT NULL,
        class_id int(11) NOT NULL,
        enrolled_at timestamp NOT NULL DEFAULT current_timestamp(),
        status enum('active','inactive') DEFAULT 'active',
        PRIMARY KEY (id),
        UNIQUE KEY unique_student_class (student_id,class_id),
        KEY class_id (class_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ class_students table checked/created');

    // Create student_enrollments table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS student_enrollments (
        id int(11) NOT NULL AUTO_INCREMENT,
        student_id int(11) NOT NULL,
        class_id int(11) NOT NULL,
        enrolled_at timestamp NOT NULL DEFAULT current_timestamp(),
        status enum('active','dropped') DEFAULT 'active',
        PRIMARY KEY (id),
        UNIQUE KEY unique_enrollment (student_id,class_id),
        KEY class_id (class_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ student_enrollments table checked/created');

    // Create reports table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS reports (
        id int(11) NOT NULL AUTO_INCREMENT,
        class_id int(11) NOT NULL,
        week int(11) NOT NULL,
        date date NOT NULL,
        course_name varchar(255) NOT NULL,
        course_code varchar(50) NOT NULL,
        lecturer_name varchar(255) NOT NULL,
        actual_students int(11) NOT NULL,
        total_students int(11) NOT NULL,
        venue varchar(255) NOT NULL,
        scheduled_time time NOT NULL,
        topic text NOT NULL,
        outcomes text NOT NULL,
        recommendations text DEFAULT NULL,
        faculty_name varchar(255) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY class_id (class_id,date)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ reports table checked/created');

    // Create feedback table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS feedback (
        id int(11) NOT NULL AUTO_INCREMENT,
        report_id int(11) NOT NULL,
        prl_id int(11) NOT NULL,
        feedback text NOT NULL,
        created_at timestamp NOT NULL DEFAULT current_timestamp(),
        PRIMARY KEY (id),
        KEY report_id (report_id),
        KEY prl_id (prl_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ feedback table checked/created');

    // Create prl_reports table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS prl_reports (
        id int(11) NOT NULL AUTO_INCREMENT,
        prl_id int(11) NOT NULL,
        program_id int(11) NOT NULL,
        title varchar(255) NOT NULL,
        content text NOT NULL,
        recommendations text DEFAULT NULL,
        priority enum('low','medium','high','urgent') DEFAULT 'medium',
        status enum('pending','reviewed','action_required','resolved') DEFAULT 'pending',
        pl_feedback text DEFAULT NULL,
        feedback_date datetime DEFAULT NULL,
        created_at timestamp NOT NULL DEFAULT current_timestamp(),
        updated_at timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
        PRIMARY KEY (id),
        KEY prl_id (prl_id),
        KEY program_id (program_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ prl_reports table checked/created');

    // Create ratings table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS ratings (
        id int(11) NOT NULL AUTO_INCREMENT,
        rater_id int(11) NOT NULL,
        ratee_id int(11) NOT NULL,
        rating int(11) NOT NULL CHECK (rating BETWEEN 1 AND 5),
        comment text DEFAULT NULL,
        created_at timestamp NOT NULL DEFAULT current_timestamp(),
        PRIMARY KEY (id),
        UNIQUE KEY rater_id (rater_id,ratee_id),
        KEY ratee_id (ratee_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ ratings table checked/created');

    // Create venues table
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS venues (
        id int(11) NOT NULL AUTO_INCREMENT,
        name varchar(100) NOT NULL,
        capacity int(11) NOT NULL,
        type enum('classroom','lab','auditorium','seminar_room') DEFAULT 'classroom',
        created_at timestamp NOT NULL DEFAULT current_timestamp(),
        active tinyint(1) DEFAULT 1,
        PRIMARY KEY (id),
        UNIQUE KEY name (name)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    console.log('✅ venues table checked/created');

    console.log('🎉 All tables checked/created successfully!');

    // Add foreign key constraints after all tables are created
    await addForeignKeys();

  } catch (error) {
    console.error('Error creating tables:', error);
  }
}

// ==============================================
// FOREIGN KEY CONSTRAINTS FUNCTION
// ==============================================

async function addForeignKeys() {
  try {
    console.log('Adding foreign key constraints...');

    // Add foreign keys for users table
    await db.promise().query(`
      ALTER TABLE users 
      ADD CONSTRAINT users_ibfk_1 FOREIGN KEY (faculty_id) REFERENCES faculties (id) ON DELETE SET NULL,
      ADD CONSTRAINT users_ibfk_2 FOREIGN KEY (stream_id) REFERENCES streams (id) ON DELETE SET NULL,
      ADD CONSTRAINT users_ibfk_3 FOREIGN KEY (program_id) REFERENCES programs (id) ON DELETE SET NULL
    `).catch(err => console.log('Users FKs might already exist'));

    // Add foreign keys for streams table
    await db.promise().query(`
      ALTER TABLE streams 
      ADD CONSTRAINT streams_ibfk_1 FOREIGN KEY (faculty_id) REFERENCES faculties (id) ON DELETE CASCADE,
      ADD CONSTRAINT streams_ibfk_2 FOREIGN KEY (prl_id) REFERENCES users (id) ON DELETE SET NULL
    `).catch(err => console.log('Streams FKs might already exist'));

    // Add foreign keys for programs table
    await db.promise().query(`
      ALTER TABLE programs 
      ADD CONSTRAINT programs_ibfk_1 FOREIGN KEY (stream_id) REFERENCES streams (id) ON DELETE CASCADE,
      ADD CONSTRAINT programs_ibfk_2 FOREIGN KEY (pl_id) REFERENCES users (id) ON DELETE SET NULL
    `).catch(err => console.log('Programs FKs might already exist'));

    // Add foreign keys for courses table
    await db.promise().query(`
      ALTER TABLE courses 
      ADD CONSTRAINT courses_ibfk_1 FOREIGN KEY (program_id) REFERENCES programs (id) ON DELETE CASCADE
    `).catch(err => console.log('Courses FKs might already exist'));

    // Add foreign keys for classes table
    await db.promise().query(`
      ALTER TABLE classes 
      ADD CONSTRAINT classes_ibfk_1 FOREIGN KEY (course_id) REFERENCES courses (id) ON DELETE CASCADE,
      ADD CONSTRAINT classes_ibfk_2 FOREIGN KEY (lecturer_id) REFERENCES users (id) ON DELETE CASCADE
    `).catch(err => console.log('Classes FKs might already exist'));

    // Add foreign keys for students table
    await db.promise().query(`
      ALTER TABLE students 
      ADD CONSTRAINT students_ibfk_1 FOREIGN KEY (program_id) REFERENCES programs (id) ON DELETE SET NULL,
      ADD CONSTRAINT students_ibfk_2 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    `).catch(err => console.log('Students FKs might already exist'));

    // Add foreign keys for attendance table
    await db.promise().query(`
      ALTER TABLE attendance 
      ADD CONSTRAINT attendance_ibfk_1 FOREIGN KEY (class_id) REFERENCES classes (id) ON DELETE CASCADE,
      ADD CONSTRAINT attendance_ibfk_3 FOREIGN KEY (marked_by) REFERENCES users (id) ON DELETE SET NULL
    `).catch(err => console.log('Attendance FKs might already exist'));

    // Add foreign keys for class_students table
    await db.promise().query(`
      ALTER TABLE class_students 
      ADD CONSTRAINT class_students_ibfk_1 FOREIGN KEY (student_id) REFERENCES users (id) ON DELETE CASCADE,
      ADD CONSTRAINT class_students_ibfk_2 FOREIGN KEY (class_id) REFERENCES classes (id) ON DELETE CASCADE
    `).catch(err => console.log('Class_students FKs might already exist'));

    // Add foreign keys for student_enrollments table
    await db.promise().query(`
      ALTER TABLE student_enrollments 
      ADD CONSTRAINT student_enrollments_ibfk_1 FOREIGN KEY (student_id) REFERENCES students (id) ON DELETE CASCADE,
      ADD CONSTRAINT student_enrollments_ibfk_2 FOREIGN KEY (class_id) REFERENCES classes (id) ON DELETE CASCADE
    `).catch(err => console.log('Student_enrollments FKs might already exist'));

    // Add foreign keys for reports table
    await db.promise().query(`
      ALTER TABLE reports 
      ADD CONSTRAINT reports_ibfk_1 FOREIGN KEY (class_id) REFERENCES classes (id) ON DELETE CASCADE
    `).catch(err => console.log('Reports FKs might already exist'));

    // Add foreign keys for feedback table
    await db.promise().query(`
      ALTER TABLE feedback 
      ADD CONSTRAINT feedback_ibfk_1 FOREIGN KEY (report_id) REFERENCES reports (id) ON DELETE CASCADE,
      ADD CONSTRAINT feedback_ibfk_2 FOREIGN KEY (prl_id) REFERENCES users (id) ON DELETE CASCADE
    `).catch(err => console.log('Feedback FKs might already exist'));

    // Add foreign keys for prl_reports table
    await db.promise().query(`
      ALTER TABLE prl_reports 
      ADD CONSTRAINT prl_reports_ibfk_1 FOREIGN KEY (prl_id) REFERENCES users (id),
      ADD CONSTRAINT prl_reports_ibfk_2 FOREIGN KEY (program_id) REFERENCES programs (id)
    `).catch(err => console.log('PRL_reports FKs might already exist'));

    // Add foreign keys for ratings table
    await db.promise().query(`
      ALTER TABLE ratings 
      ADD CONSTRAINT ratings_ibfk_1 FOREIGN KEY (rater_id) REFERENCES users (id) ON DELETE CASCADE,
      ADD CONSTRAINT ratings_ibfk_2 FOREIGN KEY (ratee_id) REFERENCES users (id) ON DELETE CASCADE
    `).catch(err => console.log('Ratings FKs might already exist'));

    console.log('✅ All foreign key constraints added successfully!');

  } catch (error) {
    console.error('Error adding foreign keys:', error);
  }
}

// JWT Secret Key from environment variables
const SECRET_KEY = process.env.SECRET_KEY;

// ==============================================
// AUTHENTICATION MIDDLEWARES
// ==============================================

/**
 * Admin Authentication Middleware
 * Verifies JWT token and checks if user has admin role
 */
const authenticateAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token', details: error.message });
  }
};

/**
 * Multi-role Authentication Middleware
 * Verifies JWT token and checks if user has one of the allowed roles
 */
const authenticateMultipleRoles = (allowedRoles) => {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      if (!allowedRoles.includes(decoded.role)) {
        return res.status(403).json({ 
          error: `Access denied. Required role: ${allowedRoles.join(', ')}` 
        });
      }
      req.user = decoded;
      next();
    } catch (error) {
      console.error('Multi-role authentication error:', error);
      res.status(401).json({ error: 'Invalid token', details: error.message });
    }
  };
};

/**
 * Program Leader (PL) Authentication Middleware
 * Verifies JWT token and checks if user has PL role
 */
const authenticatePL = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    console.log('Decoded token:', decoded);
    if (decoded.role !== 'pl') return res.status(403).json({ error: 'Program Leader access required' });
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Error in authenticatePL:', error);
    res.status(401).json({ error: 'Invalid token', details: error.message });
  }
};

/**
 * Principal Lecturer (PRL) Authentication Middleware
 * Verifies JWT token and checks if user has PRL role
 */
const authenticatePRL = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    console.log('Decoded token:', decoded);
    if (decoded.role !== 'prl') return res.status(403).json({ error: 'Principal Lecturer access required' });
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Error in authenticatePRL:', error);
    res.status(401).json({ error: 'Invalid token', details: error.message });
  }
};

/**
 * Lecturer Authentication Middleware
 * Verifies JWT token and checks if user has lecturer role
 */
const authenticateLecturer = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    if (decoded.role !== 'lecturer') {
      return res.status(403).json({ error: 'Lecturer access required' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Error in authenticateLecturer:', error);
    res.status(401).json({ error: 'Invalid token', details: error.message });
  }
};

/**
 * Student Authentication Middleware
 * Verifies JWT token and checks if user has student role
 */
const authenticateStudent = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    if (decoded.role !== 'student') {
      return res.status(403).json({ error: 'Student access required' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Error in authenticateStudent:', error);
    res.status(401).json({ error: 'Invalid token', details: error.message });
  }
};

// ==============================================
// REST OF YOUR API ENDPOINTS CONTINUE HERE...
// ==============================================

// Add your existing API endpoints below this line
// (All your /api/auth/login, /api/classes, /api/reports, etc. endpoints)



// ==============================================
// AUTHENTICATION ENDPOINTS
// ==============================================

/**
 * Verify JWT Token Endpoint
 * Validates token and returns user information
 */
app.get('/api/auth/verify', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const [users] = await db.promise().query('SELECT id, name, role, program_id, stream_id FROM users WHERE id = ?', [decoded.id]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'User not found' });
    }
    res.json(users[0]);
  } catch (error) {
    console.error('Verify error:', error);
    res.status(401).json({ error: 'Invalid token', details: error.message });
  }
});

/**
 * User Registration Endpoint
 * Creates new user account with hashed password
 */
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  try {
    const [existingUser] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.promise().query(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, email, hashedPassword, role]
    );
    res.status(201).json({ message: 'User registered', id: result.insertId });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * User Login Endpoint
 * Authenticates user and returns JWT token
 */
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Query user
    const [users] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const user = users[0];

    // Verify password
    try {
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }
    } catch (bcryptError) {
      console.error('Bcrypt error:', bcryptError.message, bcryptError.stack);
      return res.status(500).json({ error: 'Password verification failed', details: bcryptError.message });
    }

    // Check SECRET_KEY
    if (!SECRET_KEY) {
      console.error('SECRET_KEY is not defined');
      return res.status(500).json({ error: 'Server configuration error', details: 'Missing SECRET_KEY' });
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user.id, role: user.role, program_id: user.program_id, stream_id: user.stream_id },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    // Send response
    res.json({
      token,
      role: user.role,
      id: user.id,
      name: user.name,
      program_id: user.program_id,
      stream_id: user.stream_id
    });
  } catch (error) {
    console.error('Login error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// VENUE MANAGEMENT ENDPOINTS (ADMIN ONLY)
// ==============================================

/**
 * Get All Venues
 */
app.get('/api/venues', authenticateAdmin, async (req, res) => {
  try {
    const [venues] = await db.promise().query('SELECT * FROM venues ORDER BY name');
    res.json(venues);
  } catch (error) {
    console.error('Fetch venues error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Create Venue
 */
app.post('/api/venues', authenticateAdmin, async (req, res) => {
  const { name, capacity, type } = req.body;
  try {
    await db.promise().query(
      'INSERT INTO venues (name, capacity, type) VALUES (?, ?, ?)',
      [name, capacity, type || 'classroom']
    );
    res.status(201).json({ message: 'Venue created successfully' });
  } catch (error) {
    console.error('Create venue error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Update Venue
 */
app.put('/api/venues/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, capacity, type } = req.body;
  try {
    await db.promise().query(
      'UPDATE venues SET name = ?, capacity = ?, type = ? WHERE id = ?',
      [name, capacity, type, id]
    );
    res.json({ message: 'Venue updated successfully' });
  } catch (error) {
    console.error('Update venue error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Delete Venue
 */
app.delete('/api/venues/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await db.promise().query('DELETE FROM venues WHERE id = ?', [id]);
    res.json({ message: 'Venue deleted successfully' });
  } catch (error) {
    console.error('Delete venue error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// ENHANCED TIMETABLE MANAGEMENT
// ==============================================

/**
 * Enhanced Timetable Generation with Conflict Detection
 */
app.post('/api/timetable/generate-enhanced', authenticateAdmin, async (req, res) => {
  try {
    const { semester, academic_year } = req.body;
    
    // Get all unassigned classes with details
    const [unassignedClasses] = await db.promise().query(
      `SELECT 
        c.id, c.name, c.total_students, c.course_id,
        co.name AS course_name, co.code AS course_code,
        p.id AS program_id, p.name AS program_name,
        s.id AS stream_id, s.name AS stream_name,
        u.id AS lecturer_id, u.name AS lecturer_name
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       LEFT JOIN users u ON c.lecturer_id = u.id
       WHERE (c.venue IS NULL OR c.scheduled_time IS NULL OR c.semester != ?)
       AND c.active = TRUE`,
      [semester || 'Spring 2024']
    );

    // Get all available venues
    const [venues] = await db.promise().query(
      'SELECT * FROM venues WHERE active = TRUE ORDER BY capacity DESC'
    );

    if (venues.length === 0) {
      return res.status(400).json({ error: 'No venues available. Please create venues first.' });
    }

    // Enhanced time configuration
    const timeSlots = [
      { start: '08:00:00', end: '09:30:00', duration: 90 },
      { start: '09:30:00', end: '11:00:00', duration: 90 },
      { start: '11:00:00', end: '12:30:00', duration: 90 },
      { start: '13:00:00', end: '14:30:00', duration: 90 },
      { start: '14:30:00', end: '16:00:00', duration: 90 },
      { start: '16:00:00', end: '17:30:00', duration: 90 }
    ];
    
    const daysOfWeek = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
    const weeks = 16; // Typical semester length

    let assignedCount = 0;
    const conflicts = [];
    const assignments = [];

    // Get existing timetable to avoid conflicts
    const [existingTimetable] = await db.promise().query(
      `SELECT c.id, c.venue, c.scheduled_time, c.lecturer_id, c.total_students,
              co.program_id, co.id AS course_id
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       WHERE c.venue IS NOT NULL AND c.scheduled_time IS NOT NULL
       AND c.semester = ?`,
      [semester || 'Spring 2024']
    );

    for (const cls of unassignedClasses) {
      let assigned = false;
      
      // Try different days and time slots
      for (const day of daysOfWeek) {
        if (assigned) break;
        
        for (const timeSlot of timeSlots) {
          if (assigned) break;
          
          // Find suitable venue
          const suitableVenue = venues.find(venue => 
            venue.capacity >= (cls.total_students || 30) &&
            !hasVenueConflict(existingTimetable, venue.name, day, timeSlot)
          );
          
          if (suitableVenue && cls.lecturer_id) {
            // Check lecturer availability
            const lecturerConflict = hasLecturerConflict(
              existingTimetable, cls.lecturer_id, day, timeSlot
            );
            
            if (!lecturerConflict) {
              // Check program/stream conflicts (avoid same program classes at same time)
              const programConflict = hasProgramConflict(
                existingTimetable, cls.program_id, day, timeSlot
              );
              
              if (!programConflict) {
                // Assign the class
                const scheduledTime = `${academic_year || '2024-01-01'} ${timeSlot.start}`;
                
                await db.promise().query(
                  `UPDATE classes SET 
                   venue = ?, scheduled_time = ?, semester = ?, academic_year = ?
                   WHERE id = ?`,
                  [suitableVenue.name, scheduledTime, semester, academic_year, cls.id]
                );
                
                assignedCount++;
                assigned = true;
                assignments.push({
                  class: cls.name,
                  course: cls.course_name,
                  venue: suitableVenue.name,
                  day: day,
                  time: `${timeSlot.start} - ${timeSlot.end}`,
                  lecturer: cls.lecturer_name
                });
              }
            }
          }
        }
      }
      
      if (!assigned) {
        conflicts.push({
          class: cls.name,
          course: cls.course_name,
          reason: 'No suitable slot found (venue/lecturer conflicts)'
        });
      }
    }

    res.json({ 
      message: `Timetable generation completed for ${semester}`,
      summary: {
        classesAssigned: assignedCount,
        totalClasses: unassignedClasses.length,
        conflicts: conflicts.length,
        semester: semester,
        academic_year: academic_year
      },
      assignments: assignments,
      conflicts: conflicts
    });
  } catch (error) {
    console.error('Enhanced timetable generation error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Conflict detection helpers
function hasVenueConflict(existingTimetable, venue, day, timeSlot) {
  return existingTimetable.some(item => 
    item.venue === venue && 
    getDayFromDate(item.scheduled_time) === day &&
    timeOverlap(getTimeFromDate(item.scheduled_time), timeSlot)
  );
}

function hasLecturerConflict(existingTimetable, lecturerId, day, timeSlot) {
  return existingTimetable.some(item => 
    item.lecturer_id === lecturerId &&
    getDayFromDate(item.scheduled_time) === day &&
    timeOverlap(getTimeFromDate(item.scheduled_time), timeSlot)
  );
}

function hasProgramConflict(existingTimetable, programId, day, timeSlot) {
  return existingTimetable.some(item => 
    item.program_id === programId &&
    getDayFromDate(item.scheduled_time) === day &&
    timeOverlap(getTimeFromDate(item.scheduled_time), timeSlot)
  );
}

function timeOverlap(existingTime, newTimeSlot) {
  // Simple time overlap check
  return existingTime >= newTimeSlot.start && existingTime < newTimeSlot.end;
}

function getDayFromDate(dateTime) {
  const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  return days[new Date(dateTime).getDay()];
}

function getTimeFromDate(dateTime) {
  return new Date(dateTime).toTimeString().split(' ')[0];
}

// ==============================================
// TIMETABLE VIEWING ENDPOINTS
// ==============================================

/**
 * Get Complete Timetable (Admin View)
 */
app.get('/api/timetable/complete', authenticateAdmin, async (req, res) => {
  try {
    const { semester, academic_year } = req.query;
    
    const [timetable] = await db.promise().query(
      `SELECT 
        c.id, c.name AS class_name, c.venue, c.scheduled_time, c.total_students,
        co.name AS course_name, co.code AS course_code,
        p.name AS program_name, s.name AS stream_name,
        u.name AS lecturer_name, u.email AS lecturer_email,
        c.semester, c.academic_year,
        DATE_FORMAT(c.scheduled_time, '%W') AS day,
        DATE_FORMAT(c.scheduled_time, '%H:%i') AS time
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       LEFT JOIN users u ON c.lecturer_id = u.id
       WHERE c.venue IS NOT NULL AND c.scheduled_time IS NOT NULL
       AND (? IS NULL OR c.semester = ?)
       AND (? IS NULL OR c.academic_year = ?)
       ORDER BY c.scheduled_time, c.venue`,
      [semester, semester, academic_year, academic_year]
    );
    
    res.json(timetable);
  } catch (error) {
    console.error('Fetch complete timetable error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Student Timetable
 */
app.get('/api/student/timetable', authenticateStudent, async (req, res) => {
  const { id: student_id } = req.user;
  
  try {
    const [timetable] = await db.promise().query(
      `SELECT 
        c.id, c.name AS class_name, c.venue, c.scheduled_time,
        co.name AS course_name, co.code AS course_code,
        p.name AS program_name,
        u.name AS lecturer_name,
        DATE_FORMAT(c.scheduled_time, '%W') AS day,
        DATE_FORMAT(c.scheduled_time, '%H:%i') AS time,
        DATE_FORMAT(c.scheduled_time, '%Y-%m-%d') AS date,
        c.semester, c.academic_year
       FROM class_students cs
       JOIN classes c ON cs.class_id = c.id
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       LEFT JOIN users u ON c.lecturer_id = u.id
       WHERE cs.student_id = ? AND cs.status = 'active'
       AND c.venue IS NOT NULL AND c.scheduled_time IS NOT NULL
       ORDER BY c.scheduled_time`,
      [student_id]
    );
    
    res.json(timetable);
  } catch (error) {
    console.error('Fetch student timetable error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Lecturer Timetable
 */
app.get('/api/lecturer/timetable', authenticateLecturer, async (req, res) => {
  const { id: lecturer_id } = req.user;
  
  try {
    const [timetable] = await db.promise().query(
      `SELECT 
        c.id, c.name AS class_name, c.venue, c.scheduled_time, c.total_students,
        co.name AS course_name, co.code AS course_code,
        p.name AS program_name, s.name AS stream_name,
        DATE_FORMAT(c.scheduled_time, '%W') AS day,
        DATE_FORMAT(c.scheduled_time, '%H:%i') AS time,
        DATE_FORMAT(c.scheduled_time, '%Y-%m-%d') AS date,
        c.semester, c.academic_year
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       WHERE c.lecturer_id = ?
       AND c.venue IS NOT NULL AND c.scheduled_time IS NOT NULL
       ORDER BY c.scheduled_time`,
      [lecturer_id]
    );
    
    res.json(timetable);
  } catch (error) {
    console.error('Fetch lecturer timetable error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Program Leader Timetable (All classes in their program)
 */
app.get('/api/pl/timetable', authenticatePL, async (req, res) => {
  const { program_id } = req.user;
  
  try {
    const [timetable] = await db.promise().query(
      `SELECT 
        c.id, c.name AS class_name, c.venue, c.scheduled_time, c.total_students,
        co.name AS course_name, co.code AS course_code,
        u.name AS lecturer_name,
        DATE_FORMAT(c.scheduled_time, '%W') AS day,
        DATE_FORMAT(c.scheduled_time, '%H:%i') AS time,
        c.semester, c.academic_year
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       LEFT JOIN users u ON c.lecturer_id = u.id
       WHERE co.program_id = ?
       AND c.venue IS NOT NULL AND c.scheduled_time IS NOT NULL
       ORDER BY c.scheduled_time`,
      [program_id]
    );
    
    res.json(timetable);
  } catch (error) {
    console.error('Fetch PL timetable error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Principal Lecturer Timetable (All classes in their stream)
 */
app.get('/api/prl/timetable', authenticatePRL, async (req, res) => {
  const { stream_id } = req.user;
  
  try {
    const [timetable] = await db.promise().query(
      `SELECT 
        c.id, c.name AS class_name, c.venue, c.scheduled_time, c.total_students,
        co.name AS course_name, co.code AS course_code,
        p.name AS program_name,
        u.name AS lecturer_name,
        DATE_FORMAT(c.scheduled_time, '%W') AS day,
        DATE_FORMAT(c.scheduled_time, '%H:%i') AS time,
        c.semester, c.academic_year
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       LEFT JOIN users u ON c.lecturer_id = u.id
       WHERE p.stream_id = ?
       AND c.venue IS NOT NULL AND c.scheduled_time IS NOT NULL
       ORDER BY c.scheduled_time`,
      [stream_id]
    );
    
    res.json(timetable);
  } catch (error) {
    console.error('Fetch PRL timetable error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// TIMETABLE MANAGEMENT ENDPOINTS
// ==============================================

/**
 * Manual Class Scheduling (Admin/PL/PRL)
 */
app.put('/api/timetable/schedule-class/:id', authenticateMultipleRoles(['admin', 'pl', 'prl']), async (req, res) => {
  const { id } = req.params;
  const { venue, scheduled_time, semester, academic_year } = req.body;
  const user = req.user;

  try {
    // Verify class exists and user has permission
    let query = '';
    let params = [];

    if (user.role === 'admin') {
      query = 'SELECT id FROM classes WHERE id = ?';
      params = [id];
    } else if (user.role === 'pl') {
      query = `SELECT c.id FROM classes c 
               JOIN courses co ON c.course_id = co.id 
               WHERE c.id = ? AND co.program_id = ?`;
      params = [id, user.program_id];
    } else if (user.role === 'prl') {
      query = `SELECT c.id FROM classes c 
               JOIN courses co ON c.course_id = co.id 
               JOIN programs p ON co.program_id = p.id 
               WHERE c.id = ? AND p.stream_id = ?`;
      params = [id, user.stream_id];
    }

    const [classRecord] = await db.promise().query(query, params);
    if (classRecord.length === 0) {
      return res.status(404).json({ error: 'Class not found or access denied' });
    }

    // Check for conflicts
    const [conflicts] = await db.promise().query(
      `SELECT c.id, c.name, u.name AS lecturer_name
       FROM classes c
       LEFT JOIN users u ON c.lecturer_id = u.id
       WHERE c.venue = ? AND c.scheduled_time = ? AND c.id != ?
       AND c.semester = ?`,
      [venue, scheduled_time, id, semester]
    );

    if (conflicts.length > 0) {
      return res.status(400).json({ 
        error: 'Scheduling conflict detected',
        conflictWith: conflicts[0]
      });
    }

    // Update class schedule
    await db.promise().query(
      `UPDATE classes SET 
       venue = ?, scheduled_time = ?, semester = ?, academic_year = ?
       WHERE id = ?`,
      [venue, scheduled_time, semester, academic_year, id]
    );

    res.json({ message: 'Class scheduled successfully' });
  } catch (error) {
    console.error('Schedule class error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Clear Timetable for Semester (Admin Only)
 */
app.delete('/api/timetable/clear', authenticateAdmin, async (req, res) => {
  const { semester } = req.body;
  
  try {
    await db.promise().query(
      `UPDATE classes SET 
       venue = NULL, scheduled_time = NULL 
       WHERE semester = ?`,
      [semester]
    );

    res.json({ message: `Timetable cleared for ${semester}` });
  } catch (error) {
    console.error('Clear timetable error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Timetable Conflicts Report
 */
app.get('/api/timetable/conflicts', authenticateAdmin, async (req, res) => {
  try {
    const { semester } = req.query;
    
    const [conflicts] = await db.promise().query(
      `SELECT 
        c1.id AS class1_id, c1.name AS class1_name, c1.venue, c1.scheduled_time,
        c2.id AS class2_id, c2.name AS class2_name,
        u1.name AS lecturer1_name, u2.name AS lecturer2_name,
        co1.name AS course1_name, co2.name AS course2_name
       FROM classes c1
       JOIN classes c2 ON c1.venue = c2.venue 
                     AND c1.scheduled_time = c2.scheduled_time 
                     AND c1.id < c2.id
       LEFT JOIN users u1 ON c1.lecturer_id = u1.id
       LEFT JOIN users u2 ON c2.lecturer_id = u2.id
       LEFT JOIN courses co1 ON c1.course_id = co1.id
       LEFT JOIN courses co2 ON c2.course_id = co2.id
       WHERE c1.semester = ? AND c2.semester = ?
       AND c1.venue IS NOT NULL AND c2.venue IS NOT NULL`,
      [semester, semester]
    );
    
    res.json(conflicts);
  } catch (error) {
    console.error('Fetch timetable conflicts error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// PRL CLASS CAPACITY MANAGEMENT
// ==============================================

/**
 * Update Class Capacity (Principal Lecturer Only)
 */
app.put('/api/prl/classes/:id/capacity', authenticatePRL, async (req, res) => {
  const { id } = req.params;
  const { total_students } = req.body;
  const { stream_id } = req.user;

  try {
    // Verify the class belongs to PRL's stream
    const [classRecord] = await db.promise().query(
      `SELECT c.id 
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       WHERE c.id = ? AND p.stream_id = ?`,
      [id, stream_id]
    );
    
    if (classRecord.length === 0) {
      return res.status(404).json({ error: 'Class not found in your stream' });
    }

    // Update only the total_students field
    await db.promise().query(
      'UPDATE classes SET total_students = ? WHERE id = ?',
      [total_students, id]
    );

    res.json({ message: 'Class capacity updated successfully' });
  } catch (error) {
    console.error('Update class capacity error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// FACULTY MANAGEMENT ENDPOINTS (ADMIN)
// ==============================================

/**
 * Get All Faculties - Accessible by Admin, Lecturer, and Student
 */
app.get('/api/faculties', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    if (!['admin', 'lecturer','student'].includes(decoded.role)) {
      return res.status(403).json({ error: 'Admin or lecturer access required' });
    }
    db.query('SELECT id, name FROM faculties', (err, results) => {
      if (err) {
        console.error('Fetch faculties error:', err);
        return res.status(500).json({ error: 'Server error', details: err.message });
      }
      res.json(results);
    });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({ error: 'Invalid token', details: error.message });
  }
});

/**
 * Create New Faculty (Admin Only)
 */
app.post('/api/faculties', authenticateAdmin, async (req, res) => {
  const { name } = req.body;
  try {
    const [existing] = await db.promise().query('SELECT * FROM faculties WHERE name = ?', [name]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Faculty already exists' });
    }
    await db.promise().query('INSERT INTO faculties (name) VALUES (?)', [name]);
    res.status(201).json({ message: 'Faculty created' });
  } catch (error) {
    console.error('Create faculty error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Update Faculty (Admin Only)
 */
app.put('/api/faculties/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { name } = req.body;
  try {
    const [existing] = await db.promise().query('SELECT * FROM faculties WHERE name = ? AND id != ?', [name, id]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Faculty name already exists' });
    }
    await db.promise().query('UPDATE faculties SET name = ? WHERE id = ?', [name, id]);
    res.json({ message: 'Faculty updated' });
  } catch (error) {
    console.error('Update faculty error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Delete Faculty (Admin Only)
 */
app.delete('/api/faculties/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await db.promise().query('DELETE FROM faculties WHERE id = ?', [id]);
    res.json({ message: 'Faculty deleted' });
  } catch (error) {
    console.error('Delete faculty error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// STREAMS MANAGEMENT ENDPOINTS
// ==============================================

/**
 * Get Streams - Accessible by all authenticated users including students
 */
app.get('/api/streams', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const { faculty_id } = req.query;
  
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    
    // Allow all authenticated roles (admin, lecturer, student, pl, prl)
    let query, params;
    if (faculty_id) {
      query = `SELECT s.id, s.name, s.faculty_id, s.prl_id, f.name AS faculty_name
               FROM streams s
               LEFT JOIN faculties f ON s.faculty_id = f.id
               WHERE s.faculty_id = ?
               ORDER BY s.name`;
      params = [faculty_id];
    } else {
      query = `SELECT s.id, s.name, s.faculty_id, s.prl_id, f.name AS faculty_name
               FROM streams s
               LEFT JOIN faculties f ON s.faculty_id = f.id
               ORDER BY s.name`;
      params = [];
    }
    
    db.query(query, params, (err, results) => {
      if (err) {
        console.error('Fetch streams error:', err);
        return res.status(500).json({ error: 'Server error', details: err.message });
      }
      console.log('📋 Streams API response:', results.length, 'streams found');
      res.json(results);
    });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ error: 'Invalid token', details: error.message });
  }
});

app.post('/api/streams', authenticateAdmin, async (req, res) => {
  const { name, facultyId } = req.body;
  try {
    const [existing] = await db.promise().query(
      'SELECT * FROM streams WHERE name = ? AND faculty_id = ?',
      [name, facultyId]
    );
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Stream already exists in this faculty' });
    }
    await db.promise().query('INSERT INTO streams (name, faculty_id) VALUES (?, ?)', [name, facultyId]);
    res.status(201).json({ message: 'Stream created' });
  } catch (error) {
    console.error('Create stream error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Update Stream (Admin Only)
 */
app.put('/api/streams/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, facultyId } = req.body;
  try {
    const [existing] = await db.promise().query(
      'SELECT * FROM streams WHERE name = ? AND faculty_id = ? AND id != ?',
      [name, facultyId, id]
    );
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Stream name already exists in this faculty' });
    }
    await db.promise().query('UPDATE streams SET name = ?, faculty_id = ? WHERE id = ?', [name, facultyId, id]);
    res.json({ message: 'Stream updated' });
  } catch (error) {
    console.error('Update stream error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Delete Stream (Admin Only)
 */
app.delete('/api/streams/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await db.promise().query('DELETE FROM streams WHERE id = ?', [id]);
    res.json({ message: 'Stream deleted' });
  } catch (error) {
    console.error('Delete stream error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// PROGRAMS MANAGEMENT ENDPOINTS
// ==============================================

/**
 * Get Programs - Accessible by all authenticated users including students
 */
app.get('/api/programs', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const { stream_id } = req.query;
  
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    
    // Allow all authenticated roles (admin, lecturer, student, pl, prl)
    let query, params;
    if (stream_id) {
      query = `SELECT p.id, p.name, p.stream_id, p.pl_id, s.name AS stream_name
               FROM programs p
               LEFT JOIN streams s ON p.stream_id = s.id
               WHERE p.stream_id = ?
               ORDER BY p.name`;
      params = [stream_id];
    } else {
      query = `SELECT p.id, p.name, p.stream_id, p.pl_id, s.name AS stream_name
               FROM programs p
               LEFT JOIN streams s ON p.stream_id = s.id
               ORDER BY p.name`;
      params = [];
    }
    
    db.query(query, params, (err, results) => {
      if (err) {
        console.error('Fetch programs error:', err);
        return res.status(500).json({ error: 'Server error', details: err.message });
      }
      console.log('📋 Programs API response:', results.length, 'programs found');
      res.json(results);
    });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({ error: 'Invalid token', details: error.message });
  }
});

/**
 * Create Program (Admin Only)
 */
app.post('/api/programs', authenticateAdmin, async (req, res) => {
  const { name, streamId } = req.body;
  try {
    const [existing] = await db.promise().query(
      'SELECT * FROM programs WHERE name = ? AND stream_id = ?',
      [name, streamId]
    );
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Program already exists in this stream' });
    }
    await db.promise().query('INSERT INTO programs (name, stream_id) VALUES (?, ?)', [name, streamId]);
    res.status(201).json({ message: 'Program created' });
  } catch (error) {
    console.error('Create program error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Update Program (Admin Only)
 */
app.put('/api/programs/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, streamId } = req.body;
  try {
    const [existing] = await db.promise().query(
      'SELECT * FROM programs WHERE name = ? AND stream_id = ? AND id != ?',
      [name, streamId, id]
    );
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Program name already exists in this stream' });
    }
    await db.promise().query('UPDATE programs SET name = ?, stream_id = ? WHERE id = ?', [name, streamId, id]);
    res.json({ message: 'Program updated' });
  } catch (error) {
    console.error('Update program error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Delete Program (Admin Only)
 */
app.delete('/api/programs/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await db.promise().query('DELETE FROM programs WHERE id = ?', [id]);
    res.json({ message: 'Program deleted' });
  } catch (error) {
    console.error('Delete program error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// ADMIN CLASS MANAGEMENT ENDPOINTS
// ==============================================

/**
 * Get All Classes (Admin Only)
 */
app.get('/api/admin/classes', authenticateAdmin, async (req, res) => {
  try {
    const [classes] = await db.promise().query(
      `SELECT c.id, c.name, c.course_id, co.name AS course_name, co.code AS course_code,
              p.id AS program_id, p.name AS program_name,
              s.id AS stream_id, s.name AS stream_name,
              f.id AS faculty_id, f.name AS faculty_name
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       JOIN faculties f ON s.faculty_id = f.id`
    );
    res.json(classes);
  } catch (error) {
    console.error('Fetch admin classes error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Create Class (Admin Only)
 */
app.post('/api/admin/classes', authenticateAdmin, async (req, res) => {
  const { name, course_id } = req.body;
  try {
    if (!name) {
      return res.status(400).json({ error: 'Class name is required' });
    }
    if (course_id) {
      const [course] = await db.promise().query(
        `SELECT c.id FROM courses c WHERE c.id = ?`,
        [course_id]
      );
      if (course.length === 0) {
        return res.status(404).json({ error: 'Course not found' });
      }
    }
    await db.promise().query(
      'INSERT INTO classes (name, course_id) VALUES (?, ?)',
      [name, course_id || null]
    );
    res.status(201).json({ message: 'Class created' });
  } catch (error) {
    console.error('Create admin class error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Update Class (Admin Only)
 */
app.put('/api/admin/classes/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, course_id } = req.body;
  try {
    // Validate input
    if (!name || !course_id) {
      return res.status(400).json({ error: 'Class name and course ID are required' });
    }
    // Validate course exists
    const [course] = await db.promise().query(
      `SELECT c.id
       FROM courses c
       JOIN programs p ON c.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       WHERE c.id = ?`,
      [course_id]
    );
    if (course.length === 0) {
      return res.status(404).json({ error: 'Course not found' });
    }
    // Check for duplicate class name within the same course
    const [existing] = await db.promise().query(
      'SELECT * FROM classes WHERE name = ? AND course_id = ? AND id != ?',
      [name, course_id, id]
    );
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Class name already exists for this course' });
    }
    // Update class
    await db.promise().query(
      'UPDATE classes SET name = ?, course_id = ? WHERE id = ?',
      [name, course_id, id]
    );
    res.json({ message: 'Class updated' });
  } catch (error) {
    console.error('Update admin class error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Delete Class (Admin Only)
 */
app.delete('/api/admin/classes/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    // Check if class exists
    const [classRecord] = await db.promise().query('SELECT * FROM classes WHERE id = ?', [id]);
    if (classRecord.length === 0) {
      return res.status(404).json({ error: 'Class not found' });
    }
    // Delete class
    await db.promise().query('DELETE FROM classes WHERE id = ?', [id]);
    res.json({ message: 'Class deleted' });
  } catch (error) {
    console.error('Delete admin class error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// ADMIN ASSIGNMENT ENDPOINTS
// ==============================================

/**
 * Assign Principal Lecturer to Stream (Admin Only)
 */
app.post('/api/assign-prl', authenticateAdmin, async (req, res) => {
  const { streamId, prlId } = req.body;
  try {
    const [stream] = await db.promise().query('SELECT * FROM streams WHERE id = ?', [streamId]);
    if (stream.length === 0) {
      return res.status(404).json({ error: 'Stream not found' });
    }
    const [user] = await db.promise().query('SELECT * FROM users WHERE id = ? AND role = "prl"', [prlId]);
    if (user.length === 0) {
      return res.status(404).json({ error: 'Principal Lecturer not found' });
    }
    await db.promise().query('UPDATE streams SET prl_id = ? WHERE id = ?', [prlId, streamId]);
    await db.promise().query('UPDATE users SET stream_id = ? WHERE id = ?', [streamId, prlId]);
    res.json({ message: 'Principal Lecturer assigned' });
  } catch (error) {
    console.error('Assign PRL error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Unassign Principal Lecturer from Stream (Admin Only)
 */
app.post('/api/unassign-prl', authenticateAdmin, async (req, res) => {
  const { streamId } = req.body;
  try {
    await db.promise().query('UPDATE streams SET prl_id = NULL WHERE id = ?', [streamId]);
    await db.promise().query('UPDATE users SET stream_id = NULL WHERE stream_id = ?', [streamId]);
    res.json({ message: 'Principal Lecturer unassigned' });
  } catch (error) {
    console.error('Unassign PRL error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Assign Program Leader to Program (Admin Only)
 */
app.post('/api/assign-pl', authenticateAdmin, async (req, res) => {
  const { programId, plId } = req.body;
  try {
    const [program] = await db.promise().query('SELECT * FROM programs WHERE id = ?', [programId]);
    if (program.length === 0) {
      return res.status(404).json({ error: 'Program not found' });
    }
    const [user] = await db.promise().query('SELECT * FROM users WHERE id = ? AND role = "pl"', [plId]);
    if (user.length === 0) {
      return res.status(404).json({ error: 'Program Leader not found' });
    }
    await db.promise().query('UPDATE programs SET pl_id = ? WHERE id = ?', [plId, programId]);
    await db.promise().query('UPDATE users SET program_id = ? WHERE id = ?', [programId, plId]);
    res.json({ message: 'Program Leader assigned' });
  } catch (error) {
    console.error('Assign PL error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Unassign Program Leader from Program (Admin Only)
 */
app.post('/api/unassign-pl', authenticateAdmin, async (req, res) => {
  const { programId } = req.body;
  try {
    await db.promise().query('UPDATE programs SET pl_id = NULL WHERE id = ?', [programId]);
    await db.promise().query('UPDATE users SET program_id = NULL WHERE program_id = ?', [programId]);
    res.json({ message: 'Program Leader unassigned' });
  } catch (error) {
    console.error('Unassign PL error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// ADMIN USER MANAGEMENT ENDPOINTS
// ==============================================

/**
 * Get All Users (Admin Only)
 */
app.get('/api/users', authenticateAdmin, async (req, res) => {
  const { role } = req.query;
  try {
    const query = role
      ? `
        SELECT u.id, u.name, u.email, u.role, f.name AS faculty_name, s.name AS stream_name, p.name AS program_name
        FROM users u
        LEFT JOIN faculties f ON u.faculty_id = f.id
        LEFT JOIN streams s ON u.stream_id = s.id
        LEFT JOIN programs p ON u.program_id = p.id
        WHERE u.role = ?
      `
      : `
        SELECT u.id, u.name, u.email, u.role, f.name AS faculty_name, s.name AS stream_name, p.name AS program_name
        FROM users u
        LEFT JOIN faculties f ON u.faculty_id = f.id
        LEFT JOIN streams s ON u.stream_id = s.id
        LEFT JOIN programs p ON u.program_id = p.id
      `;
    const params = role ? [role] : [];
    const [users] = await db.promise().query(query, params);
    res.json(users);
  } catch (error) {
    console.error('Fetch users error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Delete User (Admin Only)
 */
app.delete('/api/users/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await db.promise().query('DELETE FROM users WHERE id = ?', [id]);
    res.json({ message: 'User deleted' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// PROGRAM LEADER (PL) ENDPOINTS
// ==============================================
/**
 * Get Lecturers for Program Leader (Only lecturers in their program)
 */
app.get('/api/pl/lecturers', authenticatePL, async (req, res) => {
  const { program_id } = req.user;
  
  try {
    const [lecturers] = await db.promise().query(
      `SELECT DISTINCT u.id, u.name, u.email, u.role
       FROM users u
       JOIN classes c ON u.id = c.lecturer_id
       JOIN courses co ON c.course_id = co.id
       WHERE u.role = 'lecturer' AND co.program_id = ?
       ORDER BY u.name`,
      [program_id]
    );
    
    res.json(lecturers);
  } catch (error) {
    console.error('Fetch PL lecturers error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Courses - Accessible by Admin and Program Leaders
 */
app.get('/api/courses', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const { program_id } = req.query;
    let query, params;

    if (decoded.role === 'admin') {
      // Admins can fetch all courses or by program_id
      query = program_id
        ? `SELECT c.id, c.name, c.code, c.program_id, p.name AS program_name
           FROM courses c
           JOIN programs p ON c.program_id = p.id
           WHERE c.program_id = ?`
        : `SELECT c.id, c.name, c.code, c.program_id, p.name AS program_name
           FROM courses c
           JOIN programs p ON c.program_id = p.id`;
      params = program_id ? [program_id] : [];
    } else if (decoded.role === 'pl') {
      // Program Leaders can only fetch courses for their program
      if (!decoded.program_id) {
        return res.status(403).json({ error: 'Program ID missing for Program Leader' });
      }
      query = `SELECT c.id, c.name, c.code, c.program_id, p.name AS program_name
               FROM courses c
               JOIN programs p ON c.program_id = p.id
               WHERE c.program_id = ?`;
      params = [decoded.program_id];
      if (program_id && program_id !== decoded.program_id) {
        return res.status(403).json({ error: 'Program Leader can only access their own program' });
      }
    } else {
      return res.status(403).json({ error: 'Program Leader or Admin access required' });
    }

    const [courses] = await db.promise().query(query, params);
    res.json(courses);
  } catch (error) {
    console.error('Fetch courses error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Create Course (Program Leader Only)
 */
app.post('/api/courses', authenticatePL, async (req, res) => {
  const { name, code } = req.body;
  const { program_id } = req.user;
  try {
    console.log('POST /api/courses - Request:', { name, code, program_id });
    if (!program_id) {
      return res.status(400).json({ error: 'Program ID is missing for this user' });
    }
    const [existing] = await db.promise().query('SELECT * FROM courses WHERE code = ?', [code]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Course code already exists' });
    }
    await db.promise().query('INSERT INTO courses (name, code, program_id) VALUES (?, ?, ?)', [name, code, program_id]);
    res.status(201).json({ message: 'Course created' });
  } catch (error) {
    console.error('Error in /api/courses:', error.message, error.stack);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Update Course (Program Leader Only)
 */
app.put('/api/courses/:id', authenticatePL, async (req, res) => {
  const { id } = req.params;
  const { name, code } = req.body;
  const { program_id } = req.user;
  try {
    const [existing] = await db.promise().query('SELECT * FROM courses WHERE code = ? AND id != ?', [code, id]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Course code already exists' });
    }
    await db.promise().query('UPDATE courses SET name = ?, code = ? WHERE id = ? AND program_id = ?', [name, code, id, program_id]);
    res.json({ message: 'Course updated' });
  } catch (error) {
    console.error('Update course error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Delete Course (Program Leader Only)
 */
app.delete('/api/courses/:id', authenticatePL, async (req, res) => {
  const { id } = req.params;
  const { program_id } = req.user;
  try {
    await db.promise().query('DELETE FROM courses WHERE id = ? AND program_id = ?', [id, program_id]);
    res.json({ message: 'Course deleted' });
  } catch (error) {
    console.error('Delete course error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Classes for Program Leader
 */
app.get('/api/classes', authenticatePL, async (req, res) => {
  const { program_id } = req.user;
  try {
    const [classes] = await db.promise().query(
      'SELECT c.id, c.name, c.course_id, c.lecturer_id, u.name AS lecturer_name, c.venue, c.scheduled_time, c.total_students, co.name AS course_name ' +
      'FROM classes c JOIN courses co ON c.course_id = co.id JOIN users u ON c.lecturer_id = u.id ' +
      'WHERE co.program_id = ?',
      [program_id]
    );
    res.json(classes);
  } catch (error) {
    console.error('Fetch classes error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Create Class (Program Leader Only)
 */
app.post('/api/classes', authenticatePL, async (req, res) => {
  const { name, course_id, lecturer_id, venue, scheduled_time, total_students } = req.body;
  const { program_id } = req.user;
  try {
    const [course] = await db.promise().query('SELECT * FROM courses WHERE id = ? AND program_id = ?', [course_id, program_id]);
    if (course.length === 0) {
      return res.status(404).json({ error: 'Course not found in your program' });
    }
    const [lecturer] = await db.promise().query('SELECT * FROM users WHERE id = ? AND role = "lecturer"', [lecturer_id]);
    if (lecturer.length === 0) {
      return res.status(404).json({ error: 'Lecturer not found' });
    }
    await db.promise().query(
      'INSERT INTO classes (name, course_id, lecturer_id, venue, scheduled_time, total_students) VALUES (?, ?, ?, ?, ?, ?)',
      [name, course_id, lecturer_id, venue, scheduled_time, total_students]
    );
    res.status(201).json({ message: 'Class created' });
  } catch (error) {
    console.error('Create class error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Update Class Capacity and Lecturer (Program Leader Only)
 */
app.put('/api/classes/:id', authenticatePL, async (req, res) => {
  const { id } = req.params;
  const { lecturer_id, total_students } = req.body;
  const { program_id } = req.user;

  try {
    console.log('PL updating class:', { id, lecturer_id, total_students, program_id });
    
    // Verify the class belongs to PL's program
    const [classRecord] = await db.promise().query(
      `SELECT c.id 
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       WHERE c.id = ? AND co.program_id = ?`,
      [id, program_id]
    );
    
    if (classRecord.length === 0) {
      return res.status(404).json({ error: 'Class not found in your program' });
    }

    // Build update query dynamically based on provided fields
    const updateFields = [];
    const updateValues = [];

    if (lecturer_id !== undefined && lecturer_id !== null) {
      // Verify lecturer exists (optional - remove if you want to allow unassigning)
      if (lecturer_id) {
        const [lecturer] = await db.promise().query(
          'SELECT id FROM users WHERE id = ? AND role = "lecturer"',
          [lecturer_id]
        );
        if (lecturer.length === 0) {
          return res.status(404).json({ error: 'Lecturer not found' });
        }
      }
      updateFields.push('lecturer_id = ?');
      updateValues.push(lecturer_id);
    }

    if (total_students !== undefined && total_students !== null) {
      updateFields.push('total_students = ?');
      updateValues.push(total_students);
    }

    // If no valid fields to update
    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    updateValues.push(id);

    // Update class
    await db.promise().query(
      `UPDATE classes SET ${updateFields.join(', ')} WHERE id = ?`,
      updateValues
    );

    console.log('Class updated successfully');
    res.json({ message: 'Class updated successfully' });
  } catch (error) {
    console.error('Update class error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Delete Class (Program Leader Only)
 */
app.delete('/api/classes/:id', authenticatePL, async (req, res) => {
  const { id } = req.params;
  const { program_id } = req.user;
  try {
    await db.promise().query(
      'DELETE c FROM classes c JOIN courses co ON c.course_id = co.id WHERE c.id = ? AND co.program_id = ?',
      [id, program_id]
    );
    res.json({ message: 'Class deleted' });
  } catch (error) {
    console.error('Delete class error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Reports for Program Leader
 */
app.get('/api/reports', authenticatePL, async (req, res) => {
  const { program_id } = req.user;
  try {
    const [reports] = await db.promise().query(
      'SELECT r.*, c.name AS class_name, co.name AS course_name, f.name AS faculty_name, u.name AS lecturer_name, fb.feedback, fb.created_at AS feedback_date ' +
      'FROM reports r JOIN classes c ON r.class_id = c.id JOIN courses co ON c.course_id = co.id ' +
      'JOIN programs p ON co.program_id = p.id JOIN faculties f ON p.stream_id = f.id ' +
      'JOIN users u ON c.lecturer_id = u.id LEFT JOIN feedback fb ON r.id = fb.report_id ' +
      'WHERE p.id = ?',
      [program_id]
    );
    res.json(reports);
  } catch (error) {
    console.error('Fetch reports error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Monitoring Data for Program Leader
 */
app.get('/api/monitoring', authenticatePL, async (req, res) => {
  const { program_id } = req.user;
  try {
    const [data] = await db.promise().query(
      'SELECT c.id, c.name AS class_name, co.name AS course_name, r.week, r.date, r.actual_students, r.total_students ' +
      'FROM classes c JOIN courses co ON c.course_id = co.id JOIN reports r ON c.id = r.class_id ' +
      'WHERE co.program_id = ?',
      [program_id]
    );
    res.json(data);
  } catch (error) {
    console.error('Fetch monitoring error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Lectures for Program Leader
 */
app.get('/api/lectures', authenticatePL, async (req, res) => {
  const { program_id } = req.user;
  try {
    const [lectures] = await db.promise().query(
      'SELECT r.id, r.class_id, c.name AS class_name, co.name AS course_name, r.topic, r.outcomes, r.recommendations, r.date ' +
      'FROM reports r JOIN classes c ON r.class_id = c.id JOIN courses co ON c.course_id = co.id ' +
      'WHERE co.program_id = ?',
      [program_id]
    );
    res.json(lectures);
  } catch (error) {
    console.error('Fetch lectures error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Ratings for Program Leader
 */
app.get('/api/ratings', authenticatePL, async (req, res) => {
  const { program_id } = req.user;
  try {
    const [ratings] = await db.promise().query(
      'SELECT r.id, r.rater_id, ur.name AS rater_name, r.ratee_id, ue.name AS ratee_name, r.rating, r.comment, r.created_at ' +
      'FROM ratings r JOIN users ur ON r.rater_id = ur.id JOIN users ue ON r.ratee_id = ue.id ' +
      'JOIN classes c ON ue.id = c.lecturer_id JOIN courses co ON c.course_id = co.id ' +
      'WHERE co.program_id = ?',
      [program_id]
    );
    res.json(ratings);
  } catch (error) {
    console.error('Fetch ratings error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Submit Rating (Program Leader Only)
 */
app.post('/api/ratings', authenticatePL, async (req, res) => {
  const { ratee_id, rating, comment } = req.body;
  const { id: rater_id, program_id } = req.user;
  try {
    const [lecturer] = await db.promise().query(
      'SELECT u.id FROM users u JOIN classes c ON u.id = c.lecturer_id JOIN courses co ON c.course_id = co.id ' +
      'WHERE u.id = ? AND co.program_id = ?',
      [ratee_id, program_id]
    );
    if (lecturer.length === 0) {
      return res.status(404).json({ error: 'Lecturer not found in your program' });
    }
    const [existing] = await db.promise().query('SELECT * FROM ratings WHERE rater_id = ? AND ratee_id = ?', [rater_id, ratee_id]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Rating already exists for this lecturer' });
    }
    await db.promise().query('INSERT INTO ratings (rater_id, ratee_id, rating, comment) VALUES (?, ?, ?, ?)', [rater_id, ratee_id, rating, comment]);
    res.status(201).json({ message: 'Rating submitted' });
  } catch (error) {
    console.error('Create rating error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// PRINCIPAL LECTURER (PRL) ENDPOINTS
// ==============================================

/**
 * Get Programs for Principal Lecturer
 */
app.get('/api/prl/programs', authenticatePRL, async (req, res) => {
  const { stream_id } = req.user;
  try {
    const [programs] = await db.promise().query(
      `SELECT p.id, p.name, p.stream_id, s.name AS stream_name, s.faculty_id, f.name AS faculty_name
       FROM programs p
       JOIN streams s ON p.stream_id = s.id
       JOIN faculties f ON s.faculty_id = f.id
       WHERE s.id = ?`,
      [stream_id]
    );
    res.json(programs);
  } catch (error) {
    console.error('Fetch PRL programs error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Courses for Principal Lecturer
 */
app.get('/api/prl/courses', authenticatePRL, async (req, res) => {
  const { stream_id } = req.user;
  try {
    const [courses] = await db.promise().query(
      `SELECT c.id, c.name, c.code, c.program_id, p.name AS program_name, f.name AS faculty_name
       FROM courses c
       JOIN programs p ON c.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       JOIN faculties f ON s.faculty_id = f.id
       WHERE s.id = ?`,
      [stream_id]
    );
    res.json(courses);
  } catch (error) {
    console.error('Fetch PRL courses error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Create Course (Principal Lecturer Only)
 */
app.post('/api/prl/courses', authenticatePRL, async (req, res) => {
  const { name, code, program_id } = req.body;
  const { stream_id } = req.user;
  try {
    console.log('POST /api/prl/courses - Request:', { name, code, program_id });
    if (!program_id) {
      return res.status(400).json({ error: 'Program ID is missing' });
    }
    const [program] = await db.promise().query(
      'SELECT * FROM programs WHERE id = ? AND stream_id = ?',
      [program_id, stream_id]
    );
    if (program.length === 0) {
      return res.status(404).json({ error: 'Program not found in your stream' });
    }
    const [existing] = await db.promise().query('SELECT * FROM courses WHERE code = ?', [code]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Course code already exists' });
    }
    await db.promise().query(
      'INSERT INTO courses (name, code, program_id) VALUES (?, ?, ?)',
      [name, code, program_id]
    );
    res.status(201).json({ message: 'Course created' });
  } catch (error) {
    console.error('Error in /api/prl/courses:', error.message, error.stack);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Update Course (Principal Lecturer Only)
 */
app.put('/api/prl/courses/:id', authenticatePRL, async (req, res) => {
  const { id } = req.params;
  const { name, code, program_id } = req.body;
  const { stream_id } = req.user;
  try {
    const [program] = await db.promise().query(
      'SELECT * FROM programs WHERE id = ? AND stream_id = ?',
      [program_id, stream_id]
    );
    if (program.length === 0) {
      return res.status(404).json({ error: 'Program not found in your stream' });
    }
    const [existing] = await db.promise().query('SELECT * FROM courses WHERE code = ? AND id != ?', [code, id]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Course code already exists' });
    }
    await db.promise().query(
      'UPDATE courses SET name = ?, code = ?, program_id = ? WHERE id = ?',
      [name, code, program_id, id]
    );
    res.json({ message: 'Course updated' });
  } catch (error) {
    console.error('Update PRL course error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Delete Course (Principal Lecturer Only)
 */
app.delete('/api/prl/courses/:id', authenticatePRL, async (req, res) => {
  const { id } = req.params;
  const { stream_id } = req.user;
  try {
    await db.promise().query(
      `DELETE c FROM courses c
       JOIN programs p ON c.program_id = p.id
       WHERE c.id = ? AND p.stream_id = ?`,
      [id, stream_id]
    );
    res.json({ message: 'Course deleted' });
  } catch (error) {
    console.error('Delete PRL course error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Classes for Principal Lecturer (Shows classes even without lecturers)
 */
app.get('/api/prl/classes', authenticatePRL, async (req, res) => {
  const { stream_id } = req.user;
  try {
    const [classes] = await db.promise().query(
      `SELECT c.id, c.name, c.course_id, c.lecturer_id, u.name AS lecturer_name, c.venue, c.scheduled_time, c.total_students, co.name AS course_name
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       LEFT JOIN users u ON c.lecturer_id = u.id  // Changed to LEFT JOIN to show unassigned classes
       WHERE p.stream_id = ?`,
      [stream_id]
    );
    res.json(classes);
  } catch (error) {
    console.error('Fetch PRL classes error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Lecturers for Principal Lecturer (Shows ALL lecturers in the stream)
 */
app.get('/api/prl/lecturers', authenticatePRL, async (req, res) => {
  const { stream_id } = req.user;
  try {
    const [lecturers] = await db.promise().query(
      `SELECT u.id, u.name, u.email, u.role, u.stream_id
       FROM users u
       WHERE u.role = 'lecturer' AND u.stream_id = ?`,  // Removed JOIN conditions to show all lecturers
      [stream_id]
    );
    res.json(lecturers);
  } catch (error) {
    console.error('Fetch PRL lecturers error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Assign Lecturer to Class (Principal Lecturer Only)
 */
app.put('/api/prl/classes/:id/assign-lecturer', authenticatePRL, async (req, res) => {
  const { id } = req.params;
  const { lecturer_id } = req.body;
  const { stream_id } = req.user;

  try {
    // Verify the class belongs to PRL's stream
    const [classRecord] = await db.promise().query(
      `SELECT c.id 
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       WHERE c.id = ? AND p.stream_id = ?`,
      [id, stream_id]
    );
    
    if (classRecord.length === 0) {
      return res.status(404).json({ error: 'Class not found in your stream' });
    }

    // Verify the lecturer belongs to PRL's stream
    const [lecturer] = await db.promise().query(
      `SELECT u.id 
       FROM users u
       WHERE u.id = ? AND u.role = 'lecturer' AND u.stream_id = ?`,
      [lecturer_id, stream_id]
    );
    
    if (lecturer.length === 0) {
      return res.status(404).json({ error: 'Lecturer not found in your stream' });
    }

    // Assign lecturer to class
    await db.promise().query(
      'UPDATE classes SET lecturer_id = ? WHERE id = ?',
      [lecturer_id, id]
    );

    res.json({ message: 'Lecturer assigned successfully' });
  } catch (error) {
    console.error('Assign lecturer error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Reports for Principal Lecturer
 */
app.get('/api/prl/reports', authenticatePRL, async (req, res) => {
  const { stream_id } = req.user;
  try {
    const [reports] = await db.promise().query(
      `SELECT 
        r.id, 
        r.class_id, 
        c.name AS class_name, 
        r.week, 
        r.date, 
        r.topic, 
        r.outcomes, 
        r.recommendations, 
        r.actual_students, 
        r.total_students,
        co.name AS course_name, 
        co.code AS course_code,
        f.name AS faculty_name, 
        u.name AS lecturer_name,
        fb.feedback
       FROM reports r
       JOIN classes c ON r.class_id = c.id
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       JOIN faculties f ON s.faculty_id = f.id
       JOIN users u ON c.lecturer_id = u.id
       LEFT JOIN feedback fb ON r.id = fb.report_id
       WHERE s.id = ?
       ORDER BY r.date DESC, r.week DESC`,
      [stream_id]
    );
    res.json(reports);
  } catch (error) {
    console.error('Fetch PRL reports error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Export All Reports as CSV (Principal Lecturer Only)
 */
app.get('/api/prl/reports/csv', authenticatePRL, async (req, res) => {
  const { stream_id } = req.user;
  try {
    const [reports] = await db.promise().query(
      `SELECT 
        r.id, 
        r.week, 
        r.date, 
        c.name AS class_name, 
        co.name AS course_name,
        co.code AS course_code,
        u.name AS lecturer_name, 
        r.topic, 
        r.outcomes,
        r.recommendations,
        r.actual_students, 
        r.total_students,
        f.name AS faculty_name,
        s.name AS stream_name,
        p.name AS program_name,
        fb.feedback
       FROM reports r
       JOIN classes c ON r.class_id = c.id
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       JOIN faculties f ON s.faculty_id = f.id
       JOIN users u ON c.lecturer_id = u.id
       LEFT JOIN feedback fb ON r.id = fb.report_id
       WHERE s.id = ?
       ORDER BY r.date DESC, r.week DESC`,
      [stream_id]
    );

    if (reports.length === 0) {
      return res.status(404).json({ error: 'No reports found' });
    }

    // Create CSV headers
    const headers = [
      'ID',
      'Week',
      'Date',
      'Class Name',
      'Course Name',
      'Course Code',
      'Lecturer Name',
      'Faculty',
      'Stream',
      'Program',
      'Topic',
      'Learning Outcomes',
      'Recommendations',
      'Actual Students',
      'Total Students',
      'Feedback'
    ];

    // Create CSV rows
    const rows = reports.map(report => [
      report.id,
      report.week,
      report.date,
      `"${report.class_name}"`,
      `"${report.course_name}"`,
      `"${report.course_code}"`,
      `"${report.lecturer_name}"`,
      `"${report.faculty_name}"`,
      `"${report.stream_name}"`,
      `"${report.program_name}"`,
      `"${report.topic}"`,
      `"${report.outcomes}"`,
      `"${report.recommendations}"`,
      report.actual_students,
      report.total_students,
      `"${report.feedback || 'No feedback'}"`
    ]);

    // Combine headers and rows
    const csvContent = [headers, ...rows]
      .map(row => row.join(','))
      .join('\n');

    res.header('Content-Type', 'text/csv');
    res.attachment(`all_reports_${new Date().toISOString().split('T')[0]}.csv`);
    res.send(csvContent);
  } catch (error) {
    console.error('CSV export error:', error);
    res.status(500).json({ error: 'Failed to export CSV', details: error.message });
  }
});

/**
 * Export Single Report as CSV (Principal Lecturer Only)
 */
app.get('/api/prl/reports/:id/csv', authenticatePRL, async (req, res) => {
  const reportId = req.params.id;
  const { stream_id } = req.user;
  
  try {
    const [reports] = await db.promise().query(
      `SELECT 
        r.id, 
        r.week, 
        r.date, 
        c.name AS class_name, 
        co.name AS course_name,
        co.code AS course_code,
        u.name AS lecturer_name, 
        r.topic, 
        r.outcomes,
        r.recommendations,
        r.actual_students, 
        r.total_students,
        f.name AS faculty_name,
        s.name AS stream_name,
        p.name AS program_name,
        fb.feedback
       FROM reports r
       JOIN classes c ON r.class_id = c.id
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       JOIN faculties f ON s.faculty_id = f.id
       JOIN users u ON c.lecturer_id = u.id
       LEFT JOIN feedback fb ON r.id = fb.report_id
       WHERE r.id = ? AND s.id = ?`,
      [reportId, stream_id]
    );

    if (reports.length === 0) {
      return res.status(404).json({ error: 'Report not found in your stream' });
    }

    const report = reports[0];
    
    // Create detailed CSV for single report
    const csvContent = [
      ['Report Details', ''],
      ['ID', report.id],
      ['Week', report.week],
      ['Date', report.date],
      ['Class Name', report.class_name],
      ['Course Name', report.course_name],
      ['Course Code', report.course_code],
      ['Lecturer', report.lecturer_name],
      ['Faculty', report.faculty_name],
      ['Stream', report.stream_name],
      ['Program', report.program_name],
      ['', ''],
      ['Topic Covered', report.topic],
      ['', ''],
      ['Learning Outcomes', report.outcomes],
      ['', ''],
      ['Recommendations', report.recommendations],
      ['', ''],
      ['Attendance', ''],
      ['Actual Students Present', report.actual_students],
      ['Total Registered Students', report.total_students],
      ['', ''],
      ['PRL Feedback', report.feedback || 'No feedback provided']
    ].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');

    res.header('Content-Type', 'text/csv');
    res.attachment(`report_${reportId}_${report.class_name}.csv`);
    res.send(csvContent);
  } catch (error) {
    console.error('CSV export single error:', error);
    res.status(500).json({ error: 'Failed to export CSV', details: error.message });
  }
});

/**
 * Add Feedback to Report (Principal Lecturer Only)
 */
app.post('/api/prl/reports/:id/feedback', authenticatePRL, async (req, res) => {
  const { id } = req.params;
  const { feedback } = req.body;
  const { stream_id } = req.user;

  try {
    // Verify the report belongs to PRL's stream
    const [report] = await db.promise().query(
      `SELECT r.id 
       FROM reports r
       JOIN classes c ON r.class_id = c.id
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       WHERE r.id = ? AND s.id = ?`,
      [id, stream_id]
    );
    
    if (report.length === 0) {
      return res.status(404).json({ error: 'Report not found in your stream' });
    }

    // Check if feedback already exists
    const [existingFeedback] = await db.promise().query(
      'SELECT id FROM feedback WHERE report_id = ?',
      [id]
    );

    if (existingFeedback.length > 0) {
      // Update existing feedback
      await db.promise().query(
        'UPDATE feedback SET feedback = ? WHERE report_id = ?',
        [feedback, id]
      );
    } else {
      // Create new feedback
      await db.promise().query(
        'INSERT INTO feedback (report_id, feedback) VALUES (?, ?)',
        [id, feedback]
      );
    }

    res.json({ message: 'Feedback submitted successfully' });
  } catch (error) {
    console.error('Submit feedback error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Monitoring Data for Principal Lecturer
 */
app.get('/api/prl/monitoring', authenticatePRL, async (req, res) => {
  const { stream_id } = req.user;
  try {
    const [data] = await db.promise().query(
      `SELECT c.id, c.name AS class_name, co.name AS course_name, r.week, r.date, r.actual_students, r.total_students
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN reports r ON c.id = r.class_id
       JOIN programs p ON co.program_id = p.id
       WHERE p.stream_id = ?`,
      [stream_id]
    );
    res.json(data);
  } catch (error) {
    console.error('Fetch PRL monitoring error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Lectures for Principal Lecturer
 */
app.get('/api/prl/lectures', authenticatePRL, async (req, res) => {
  const { stream_id } = req.user;
  try {
    const [lectures] = await db.promise().query(
      `SELECT r.id, r.class_id, c.name AS class_name, co.name AS course_name, r.topic, r.outcomes, r.recommendations, r.date
       FROM reports r
       JOIN classes c ON r.class_id = c.id
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       WHERE p.stream_id = ?`,
      [stream_id]
    );
    res.json(lectures);
  } catch (error) {
    console.error('Fetch PRL lectures error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Ratings for Principal Lecturer
 */
app.get('/api/prl/ratings', authenticatePRL, async (req, res) => {
  const { stream_id } = req.user;
  try {
    const [ratings] = await db.promise().query(
      `SELECT r.id, r.rater_id, ur.name AS rater_name, r.ratee_id, ue.name AS ratee_name, r.rating, r.comment, r.created_at
       FROM ratings r
       JOIN users ur ON r.rater_id = ur.id
       JOIN users ue ON r.ratee_id = ue.id
       JOIN classes c ON ue.id = c.lecturer_id
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       WHERE p.stream_id = ?`,
      [stream_id]
    );
    res.json(ratings);
  } catch (error) {
    console.error('Fetch PRL ratings error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Submit Rating (Principal Lecturer Only)
 */
app.post('/api/prl/ratings', authenticatePRL, async (req, res) => {
  const { ratee_id, rating, comment } = req.body;
  const { id: rater_id, stream_id } = req.user;
  try {
    const [lecturer] = await db.promise().query(
      `SELECT u.id
       FROM users u
       JOIN classes c ON u.id = c.lecturer_id
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       WHERE u.id = ? AND p.stream_id = ?`,
      [ratee_id, stream_id]
    );
    if (lecturer.length === 0) {
      return res.status(404).json({ error: 'Lecturer not found in your stream' });
    }
    const [existing] = await db.promise().query(
      'SELECT * FROM ratings WHERE rater_id = ? AND ratee_id = ?',
      [rater_id, ratee_id]
    );
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Rating already exists for this lecturer' });
    }
    await db.promise().query(
      'INSERT INTO ratings (rater_id, ratee_id, rating, comment) VALUES (?, ?, ?, ?)',
      [rater_id, ratee_id, rating, comment]
    );
    res.status(201).json({ message: 'Rating submitted' });
  } catch (error) {
    console.error('Create PRL rating error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// LECTURER ENDPOINTS
// ==============================================

/**
 * Get Lecturer Profile
 */
app.get('/api/lecturer/profile', authenticateLecturer, async (req, res) => {
  const { id } = req.user;
  try {
    const [profile] = await db.promise().query(
      `SELECT faculty_id, stream_id, profile_set
       FROM users
       WHERE id = ?`,
      [id]
    );
    if (profile.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(profile[0]);
  } catch (error) {
    console.error('Fetch lecturer profile error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Set Lecturer Profile
 */
app.post('/api/lecturer/profile', authenticateLecturer, async (req, res) => {
  const { faculty_id, stream_id } = req.body;
  const { id } = req.user;
  try {
    const [user] = await db.promise().query('SELECT profile_set FROM users WHERE id = ?', [id]);
    if (user.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (user[0].profile_set) {
      return res.status(403).json({ error: 'Profile already set' });
    }
    if (!faculty_id || !stream_id) {
      return res.status(400).json({ error: 'Faculty ID and Stream ID are required' });
    }
    const [faculty] = await db.promise().query('SELECT id FROM faculties WHERE id = ?', [faculty_id]);
    if (faculty.length === 0) {
      return res.status(404).json({ error: 'Faculty not found' });
    }
    const [stream] = await db.promise().query(
      `SELECT s.id
       FROM streams s
       JOIN users u ON u.stream_id = s.id
       WHERE s.id = ? AND u.role = 'prl'`,
      [stream_id]
    );
    if (stream.length === 0) {
      return res.status(404).json({ error: 'Stream with Principal Lecturer not found' });
    }
    await db.promise().query(
      'UPDATE users SET faculty_id = ?, stream_id = ?, profile_set = TRUE WHERE id = ?',
      [faculty_id, stream_id, id]
    );
    res.json({ message: 'Profile set successfully' });
  } catch (error) {
    console.error('Set lecturer profile error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get PRLs by Faculty (Accessible to admins and lecturers)
 */
app.get('/api/prls-by-faculty/:faculty_id', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    if (!['admin', 'lecturer'].includes(decoded.role)) {
      return res.status(403).json({ error: 'Admin or lecturer access required' });
    }

    const { faculty_id } = req.params;
    
    const query = `
      SELECT u.id, u.name, u.email, u.role, u.stream_id, s.name AS stream_name
      FROM users u
      JOIN streams s ON u.stream_id = s.id
      WHERE u.role = 'prl' AND s.faculty_id = ?
    `;
    
    db.query(query, [faculty_id], (err, results) => {
      if (err) {
        console.error('Fetch PRLs by faculty error:', err);
        return res.status(500).json({ error: 'Server error', details: err.message });
      }
      res.json(results);
    });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({ error: 'Invalid token', details: error.message });
  }
});

// ==============================================
// LECTURER CLASSES AND REPORTS ENDPOINTS
// ==============================================

/**
 * Get Classes Assigned to Lecturer
 */
app.get('/api/lecturer/classes', authenticateLecturer, async (req, res) => {
  const { id } = req.user;
  try {
    const [classes] = await db.promise().query(
      `SELECT 
        c.id, 
        c.name, 
        c.course_id, 
        c.lecturer_id, 
        c.venue, 
        c.scheduled_time, 
        c.total_students, 
        co.name AS course_name, 
        co.code AS course_code,
        p.name AS program_name, 
        s.name AS stream_name, 
        f.name AS faculty_name
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       JOIN faculties f ON s.faculty_id = f.id
       WHERE c.lecturer_id = ?
       ORDER BY c.name ASC`,
      [id]
    );
    res.json(classes);
  } catch (error) {
    console.error('Fetch lecturer classes error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Reports Submitted by Lecturer
 */
app.get('/api/lecturer/reports', authenticateLecturer, async (req, res) => {
  const { id } = req.user;
  try {
    const [reports] = await db.promise().query(
      `SELECT 
        r.id, 
        r.class_id, 
        c.name AS class_name, 
        r.week, 
        r.date, 
        r.topic, 
        r.outcomes, 
        r.recommendations, 
        r.actual_students, 
        r.total_students,
        fb.feedback,
        co.name AS course_name,
        f.name AS faculty_name
       FROM reports r
       JOIN classes c ON r.class_id = c.id
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       JOIN faculties f ON s.faculty_id = f.id
       LEFT JOIN feedback fb ON r.id = fb.report_id
       WHERE c.lecturer_id = ?
       ORDER BY r.date DESC, r.week DESC`,
      [id]
    );
    res.json(reports);
  } catch (error) {
    console.error('Fetch lecturer reports error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Submit New Report (Lecturer Only)
 */
app.post('/api/lecturer/reports', authenticateLecturer, async (req, res) => {
  const { class_id, week, date, topic, outcomes, recommendations, actual_students } = req.body;
  const { id: lecturer_id } = req.user;

  try {
    // Verify the class belongs to the lecturer and get class details
    const [classRecord] = await db.promise().query(
      `SELECT c.id, c.total_students, co.name AS course_name, f.name AS faculty_name
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       JOIN faculties f ON s.faculty_id = f.id
       WHERE c.id = ? AND c.lecturer_id = ?`,
      [class_id, lecturer_id]
    );
    
    if (classRecord.length === 0) {
      return res.status(404).json({ error: 'Class not found or not assigned to you' });
    }

    // Validate actual students doesn't exceed total students
    if (parseInt(actual_students) > parseInt(classRecord[0].total_students)) {
      return res.status(400).json({ 
        error: `Actual students present (${actual_students}) cannot exceed total registered students (${classRecord[0].total_students})` 
      });
    }

    // Check if report already exists for this class and week
    const [existingReport] = await db.promise().query(
      'SELECT id FROM reports WHERE class_id = ? AND week = ?',
      [class_id, week]
    );

    if (existingReport.length > 0) {
      return res.status(400).json({ error: 'Report already exists for this class and week' });
    }

    // Create the report
    const [result] = await db.promise().query(
      `INSERT INTO reports (class_id, week, date, topic, outcomes, recommendations, actual_students, total_students)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [class_id, week, date, topic, outcomes, recommendations, actual_students, classRecord[0].total_students]
    );

    res.status(201).json({ 
      message: 'Report submitted successfully',
      reportId: result.insertId
    });
  } catch (error) {
    console.error('Create report error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Reports for Specific Class (Lecturer Only)
 */
app.get('/api/lecturer/classes/:id/reports', authenticateLecturer, async (req, res) => {
  const { id } = req.params;
  const lecturer_id = req.user.id;

  try {
    // Verify the class belongs to the lecturer
    const [classRecord] = await db.promise().query(
      'SELECT id FROM classes WHERE id = ? AND lecturer_id = ?',
      [id, lecturer_id]
    );

    if (classRecord.length === 0) {
      return res.status(404).json({ error: 'Class not found or not assigned to you' });
    }

    const [reports] = await db.promise().query(
      `SELECT 
        r.id, 
        r.week, 
        r.date, 
        r.topic, 
        r.outcomes, 
        r.recommendations, 
        r.actual_students, 
        r.total_students,
        fb.feedback
       FROM reports r
       LEFT JOIN feedback fb ON r.id = fb.report_id
       WHERE r.class_id = ?
       ORDER BY r.week DESC, r.date DESC`,
      [id]
    );

    res.json(reports);
  } catch (error) {
    console.error('Fetch class reports error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// LECTURER MONITORING & ATTENDANCE ENDPOINTS
// ==============================================

/**
 * Get Ratings for Current Lecturer
 */
app.get('/api/lecturer/ratings', authenticateLecturer, async (req, res) => {
  const { id: lecturer_id } = req.user;
  
  try {
    const [ratings] = await db.promise().query(
      `SELECT 
        r.id,
        r.rater_id,
        ur.name AS rater_name,
        ur.role AS rater_role,
        r.ratee_id,
        ue.name AS ratee_name,
        r.rating,
        r.comment,
        r.created_at
      FROM ratings r
      JOIN users ur ON r.rater_id = ur.id
      JOIN users ue ON r.ratee_id = ue.id
      WHERE r.ratee_id = ?
      ORDER BY r.created_at DESC`,
      [lecturer_id]
    );
    
    res.json(ratings);
  } catch (error) {
    console.error('Fetch lecturer ratings error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Monitoring Data for Lecturer
 */
app.get('/api/lecturer/monitoring', authenticateLecturer, async (req, res) => {
  const { id: lecturer_id } = req.user;
  
  try {
    const [reports] = await db.promise().query(
      `SELECT 
        r.id,
        r.class_id,
        c.name AS class_name,
        r.week,
        r.date,
        r.actual_students,
        r.total_students,
        r.topic,
        fb.feedback,
        // Calculate attendance percentage for better insights
        ROUND((r.actual_students / r.total_students) * 100, 1) AS attendance_percentage
      FROM reports r
      JOIN classes c ON r.class_id = c.id
      LEFT JOIN feedback fb ON r.id = fb.report_id
      WHERE c.lecturer_id = ?
      ORDER BY r.date DESC, r.week DESC
      LIMIT 10`,
      [lecturer_id]
    );
    
    res.json(reports);
  } catch (error) {
    console.error('Fetch lecturer monitoring error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Attendance for Specific Class - CORRECTED VERSION
 */
app.get('/api/lecturer/classes/:id/attendance', authenticateLecturer, async (req, res) => {
  const classId = req.params.id;
  const lecturer_id = req.user.id;
  const today = new Date().toISOString().split('T')[0];
  
  try {
    // Verify the class belongs to the lecturer
    const [classRecord] = await db.promise().query(
      'SELECT id, name, total_students FROM classes WHERE id = ? AND lecturer_id = ?',
      [classId, lecturer_id]
    );

    if (classRecord.length === 0) {
      return res.status(404).json({ error: 'Class not found or not assigned to you' });
    }

    // CORRECTED QUERY: Using users table instead of students table
    const [attendance] = await db.promise().query(
      `SELECT 
        u.id,
        u.name,
        u.student_id,
        u.email,
        IFNULL(a.present, false) AS today_attendance,
        a.date AS attendance_date
      FROM users u
      JOIN class_students cs ON u.id = cs.student_id
      LEFT JOIN attendance a ON u.id = a.student_id AND a.class_id = ? AND a.date = ?
      WHERE cs.class_id = ? AND cs.status = 'active' AND u.role = 'student'
      ORDER BY u.name ASC`,
      [classId, today, classId]
    );
    
    res.json(attendance);
  } catch (error) {
    console.error('Fetch class attendance error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Mark Individual Student Attendance - FIXED VERSION
 */
app.post('/api/lecturer/attendance', authenticateLecturer, async (req, res) => {
  const { class_id, student_id, present, date } = req.body;
  const lecturer_id = req.user.id;
  
  try {
    console.log('Marking attendance:', { class_id, student_id, present, date, lecturer_id });

    // Verify the class belongs to the lecturer
    const [classRecord] = await db.promise().query(
      'SELECT id, name FROM classes WHERE id = ? AND lecturer_id = ?',
      [class_id, lecturer_id]
    );

    if (classRecord.length === 0) {
      console.log('Class verification failed:', { class_id, lecturer_id });
      return res.status(404).json({ 
        error: 'Class not found or not assigned to you' 
      });
    }

    // Verify student exists and is a student
    const [student] = await db.promise().query(
      'SELECT id, name FROM users WHERE id = ? AND role = "student"',
      [student_id]
    );

    if (student.length === 0) {
      console.log('Student verification failed:', { student_id });
      return res.status(404).json({ 
        error: 'Student not found' 
      });
    }

    // Check if student is enrolled in this class
    const [enrollment] = await db.promise().query(
      'SELECT id FROM class_students WHERE class_id = ? AND student_id = ? AND status = "active"',
      [class_id, student_id]
    );

    if (enrollment.length === 0) {
      console.log('Enrollment verification failed:', { class_id, student_id });
      return res.status(404).json({ 
        error: 'Student not enrolled in this class' 
      });
    }

    // Check if attendance already exists for this student on this date
    const [existing] = await db.promise().query(
      'SELECT id FROM attendance WHERE class_id = ? AND student_id = ? AND date = ?',
      [class_id, student_id, date]
    );

    if (existing.length > 0) {
      // Update existing attendance record
      await db.promise().query(
        'UPDATE attendance SET present = ?, marked_by = ? WHERE id = ?',
        [present, lecturer_id, existing[0].id]
      );
      console.log(`Updated attendance: Class ${class_id}, Student ${student_id}, Present: ${present}, Date: ${date}`);
    } else {
      // Create new attendance record in database
      await db.promise().query(
        'INSERT INTO attendance (class_id, student_id, date, present, marked_by) VALUES (?, ?, ?, ?, ?)',
        [class_id, student_id, date, present, lecturer_id]
      );
      console.log(`Created attendance: Class ${class_id}, Student ${student_id}, Present: ${present}, Date: ${date}`);
    }

    res.json({ message: 'Attendance marked successfully' });
  } catch (error) {
    console.error('Mark attendance error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Attendance Count for Specific Class and Date - FOR REPORTS
 */
app.get('/api/lecturer/classes/:id/attendance-count', authenticateLecturer, async (req, res) => {
  const classId = req.params.id;
  const { date } = req.query; // Get date from query parameters
  const lecturer_id = req.user.id;
  
  try {
    console.log('Fetching attendance count for report:', { classId, date, lecturer_id });

    // Verify the class belongs to the lecturer
    const [classRecord] = await db.promise().query(
      'SELECT id, name, total_students FROM classes WHERE id = ? AND lecturer_id = ?',
      [classId, lecturer_id]
    );

    if (classRecord.length === 0) {
      return res.status(404).json({ error: 'Class not found or not assigned to you' });
    }

    // Get count of present students for the specific date
    const [attendanceCount] = await db.promise().query(
      `SELECT 
        COUNT(*) as total_present
      FROM attendance a
      JOIN class_students cs ON a.student_id = cs.student_id AND a.class_id = cs.class_id
      WHERE a.class_id = ? AND a.date = ? AND a.present = true AND cs.status = 'active'`,
      [classId, date]
    );

    // Get total enrolled students
    const [totalStudents] = await db.promise().query(
      `SELECT COUNT(*) as total_enrolled
       FROM class_students 
       WHERE class_id = ? AND status = 'active'`,
      [classId]
    );

    const result = {
      present_count: attendanceCount[0]?.total_present || 0,
      total_enrolled: totalStudents[0]?.total_enrolled || 0,
      class_total_students: classRecord[0].total_students,
      date: date
    };

    console.log('Attendance count result:', result);
    res.json(result);
  } catch (error) {
    console.error('Fetch attendance count error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Mark Bulk Attendance for Class - UPDATED VERSION
 */
app.post('/api/lecturer/attendance/bulk', authenticateLecturer, async (req, res) => {
  const { class_id, present_students, date } = req.body;
  const lecturer_id = req.user.id;
  
  try {
    // Verify the class belongs to the lecturer
    const [classRecord] = await db.promise().query(
      'SELECT id, name FROM classes WHERE id = ? AND lecturer_id = ?',
      [class_id, lecturer_id]
    );

    if (classRecord.length === 0) {
      return res.status(404).json({ error: 'Class not found or not assigned to you' });
    }

    // Start transaction for atomic bulk operations
    await db.promise().query('START TRANSACTION');

    try {
      // Clear existing attendance for this class and date to avoid duplicates
      await db.promise().query(
        'DELETE FROM attendance WHERE class_id = ? AND date = ?',
        [class_id, date]
      );

      // Insert new attendance records for present students
      for (const student_id of present_students) {
        // Verify student is enrolled in this class before marking attendance
        const [enrollment] = await db.promise().query(
          'SELECT id FROM class_students WHERE class_id = ? AND student_id = ? AND status = "active"',
          [class_id, student_id]
        );

        if (enrollment.length > 0) {
          await db.promise().query(
            'INSERT INTO attendance (class_id, student_id, date, present, marked_by) VALUES (?, ?, ?, ?, ?)',
            [class_id, student_id, date, true, lecturer_id]
          );
        }
      }

      await db.promise().query('COMMIT');
      console.log(`Bulk attendance completed: Class ${class_id}, ${present_students.length} students marked present, Date: ${date}`);
      
      res.json({ 
        message: 'Bulk attendance marked successfully',
        students_marked: present_students.length
      });
    } catch (error) {
      await db.promise().query('ROLLBACK');
      throw error;
    }
  } catch (error) {
    console.error('Bulk attendance error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// STUDENT MANAGEMENT ENDPOINTS (ADMIN)
// ==============================================

/**
 * Get All Students (Admin Only)
 */
app.get('/api/admin/students', authenticateAdmin, async (req, res) => {
  try {
    const [students] = await db.promise().query(
      `SELECT 
        u.id,
        u.name,
        u.email,
        u.student_id,
        u.profile_set,
        u.program_id,
        p.name AS program_name
       FROM users u
       LEFT JOIN programs p ON u.program_id = p.id
       WHERE u.role = 'student'
       ORDER BY u.name`
    );
    
    res.json(students);
  } catch (error) {
    console.error('Fetch students error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Assign Student ID to User (Admin Only)
 */
app.put('/api/admin/students/:id/assign-id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { student_id } = req.body;
  
  try {
    // Check if user exists and is a student
    const [user] = await db.promise().query(
      'SELECT id, name, email FROM users WHERE id = ? AND role = "student"',
      [id]
    );
    
    if (user.length === 0) {
      return res.status(404).json({ error: 'Student user not found' });
    }

    // Check if student ID is unique
    const [existingStudent] = await db.promise().query(
      'SELECT id FROM users WHERE student_id = ? AND id != ?',
      [student_id, id]
    );
    
    if (existingStudent.length > 0) {
      return res.status(400).json({ error: 'Student ID already exists' });
    }

    // Update the user with student_id
    await db.promise().query(
      'UPDATE users SET student_id = ? WHERE id = ?',
      [student_id, id]
    );

    res.json({ 
      message: 'Student ID assigned successfully',
      student_id: student_id
    });
  } catch (error) {
    console.error('Assign student ID error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Delete Student (Admin Only)
 */
app.delete('/api/admin/students/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  
  try {
    // Check if user exists and is a student
    const [user] = await db.promise().query(
      'SELECT id FROM users WHERE id = ? AND role = "student"',
      [id]
    );

    if (user.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    // Delete the user
    await db.promise().query('DELETE FROM users WHERE id = ?', [id]);

    res.json({ message: 'Student deleted successfully' });
  } catch (error) {
    console.error('Delete student error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// STUDENT PROFILE & DASHBOARD ENDPOINTS
// ==============================================

/**
 * Check Student Profile Status
 */
app.get('/api/student/profile', authenticateStudent, async (req, res) => {
  const { id: user_id } = req.user;
  
  try {
    const [student] = await db.promise().query(
      `SELECT 
        u.id,
        u.name, 
        u.email, 
        u.student_id,
        u.profile_set,
        u.program_id,
        p.name AS program_name, 
        s.name AS stream_name, 
        f.name AS faculty_name
       FROM users u
       LEFT JOIN programs p ON u.program_id = p.id
       LEFT JOIN streams s ON p.stream_id = s.id
       LEFT JOIN faculties f ON s.faculty_id = f.id
       WHERE u.id = ? AND u.role = 'student'`,
      [user_id]
    );
    
    if (student.length === 0) {
      return res.status(404).json({ error: 'Student profile not found' });
    }
    
    const studentData = student[0];
    
    res.json({ 
      profile_set: studentData.profile_set,
      has_student_id: !!studentData.student_id,
      ...studentData
    });
  } catch (error) {
    console.error('Check student profile error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Student Profile Setup
 */
app.post('/api/student/profile', authenticateStudent, async (req, res) => {
  const { program_id } = req.body;
  const { id: user_id } = req.user;
  
  try {
    // Check if student has been assigned a student_id
    const [studentRecord] = await db.promise().query(
      'SELECT student_id FROM users WHERE id = ? AND role = "student"',
      [user_id]
    );
    
    if (studentRecord.length === 0) {
      return res.status(404).json({ error: 'Student record not found' });
    }
    
    if (!studentRecord[0].student_id) {
      return res.status(400).json({ 
        error: 'Student ID not assigned yet. Please wait for administrator to assign your Student ID.' 
      });
    }

    // Get program details to verify it exists
    const [program] = await db.promise().query(
      `SELECT p.id, p.name, p.stream_id, s.faculty_id 
       FROM programs p 
       JOIN streams s ON p.stream_id = s.id 
       WHERE p.id = ?`,
      [program_id]
    );

    if (program.length === 0) {
      return res.status(400).json({ error: 'Invalid program selected' });
    }

    // Update student with program information and mark profile as set
    await db.promise().query(
      'UPDATE users SET program_id = ?, profile_set = TRUE WHERE id = ?',
      [program_id, user_id]
    );

    res.json({ 
      message: 'Profile setup successful',
      program_name: program[0].name
    });
  } catch (error) {
    console.error('Setup student profile error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Student Dashboard Statistics
 */
app.get('/api/student/dashboard/stats', authenticateStudent, async (req, res) => {
  const { id: user_id } = req.user;
  
  try {
    // Get student basic info
    const [student] = await db.promise().query(
      `SELECT 
        u.id,
        u.name,
        u.email,
        u.student_id,
        u.profile_set,
        u.program_id,
        p.name AS program_name,
        s.name AS stream_name,
        f.name AS faculty_name
       FROM users u
       LEFT JOIN programs p ON u.program_id = p.id
       LEFT JOIN streams s ON p.stream_id = s.id
       LEFT JOIN faculties f ON s.faculty_id = f.id
       WHERE u.id = ? AND u.role = 'student'`,
      [user_id]
    );

    if (student.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const studentData = student[0];

    // Get classes count for the student
    const [classes] = await db.promise().query(
      `SELECT COUNT(*) as class_count 
       FROM class_students 
       WHERE student_id = ? AND status = 'active'`,
      [user_id]
    );

    // Get enrolled courses count
    const [courses] = await db.promise().query(
      `SELECT COUNT(DISTINCT c.course_id) as course_count
       FROM class_students cs
       JOIN classes c ON cs.class_id = c.id
       WHERE cs.student_id = ? AND cs.status = 'active'`,
      [user_id]
    );

    // Get attendance data (placeholder - you can implement actual attendance logic)
    const attendanceRate = 85; // Placeholder - implement actual calculation

    // Get pending assignments/tasks (placeholder)
    const pendingAssignments = 0; // Placeholder

    res.json({
      student: {
        name: studentData.name,
        student_id: studentData.student_id,
        program: studentData.program_name,
        faculty: studentData.faculty_name,
        stream: studentData.stream_name,
        profile_set: studentData.profile_set
      },
      stats: {
        totalClasses: classes[0].class_count || 0,
        enrolledCourses: courses[0].course_count || 0,
        attendanceRate: attendanceRate,
        pendingAssignments: pendingAssignments
      }
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Student's Upcoming Classes
 */
app.get('/api/student/upcoming-classes', authenticateStudent, async (req, res) => {
  const { id: user_id } = req.user;
  
  try {
    const today = new Date().toISOString().split('T')[0];
    
    const [classes] = await db.promise().query(
      `SELECT 
        c.id,
        c.name AS class_name,
        co.name AS course_name,
        co.code AS course_code,
        u.name AS lecturer_name,
        c.venue,
        c.scheduled_time,
        DATE_FORMAT(c.scheduled_time, '%H:%i') AS time,
        'Scheduled' AS status
       FROM class_students cs
       JOIN classes c ON cs.class_id = c.id
       JOIN courses co ON c.course_id = co.id
       JOIN users u ON c.lecturer_id = u.id
       WHERE cs.student_id = ? 
         AND cs.status = 'active'
         AND DATE(c.scheduled_time) = ?
       ORDER BY c.scheduled_time ASC`,
      [user_id, today]
    );

    res.json(classes);
  } catch (error) {
    console.error('Fetch upcoming classes error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Available Classes for Student Enrollment
 */
app.get('/api/student/available-classes', authenticateStudent, async (req, res) => {
  const { id: user_id } = req.user;
  
  try {
    // Get student's program
    const [student] = await db.promise().query(
      'SELECT program_id FROM users WHERE id = ? AND role = "student"',
      [user_id]
    );

    if (student.length === 0 || !student[0].program_id) {
      return res.status(404).json({ error: 'Student program not found' });
    }

    const program_id = student[0].program_id;

    // Get classes that are in the student's program and not already enrolled
    const [classes] = await db.promise().query(
      `SELECT 
        c.id,
        c.name AS class_name,
        co.name AS course_name,
        co.code AS course_code,
        u.name AS lecturer_name,
        c.venue,
        c.scheduled_time,
        c.total_students,
        (SELECT COUNT(*) FROM class_students WHERE class_id = c.id AND status = 'active') AS enrolled_students,
        IF(cs.id IS NOT NULL, true, false) AS is_enrolled
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN users u ON c.lecturer_id = u.id
       LEFT JOIN class_students cs ON c.id = cs.class_id AND cs.student_id = ? AND cs.status = 'active'
       WHERE co.program_id = ?
       ORDER BY co.name, c.name`,
      [user_id, program_id]
    );

    res.json(classes);
  } catch (error) {
    console.error('Fetch available classes error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Student's Enrolled Classes
 */
app.get('/api/student/classes', authenticateStudent, async (req, res) => {
  const { id: user_id } = req.user;
  
  try {
    const [classes] = await db.promise().query(
      `SELECT 
        c.id,
        c.name AS class_name,
        co.name AS course_name,
        co.code AS course_code,
        u.name AS lecturer_name,
        c.venue,
        c.scheduled_time,
        c.total_students,
        (SELECT COUNT(*) FROM class_students WHERE class_id = c.id AND status = 'active') AS enrolled_students
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN users u ON c.lecturer_id = u.id
       JOIN class_students cs ON c.id = cs.class_id 
       WHERE cs.student_id = ? AND cs.status = 'active'
       ORDER BY co.name, c.name`,
      [user_id]
    );

    res.json(classes);
  } catch (error) {
    console.error('Fetch student classes error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Enroll in Class
 */
app.post('/api/student/classes/:id/enroll', authenticateStudent, async (req, res) => {
  const { id: class_id } = req.params;
  const { id: user_id } = req.user;
  
  try {
    // Check if class exists and get class details
    const [classRecord] = await db.promise().query(
      `SELECT c.id, c.total_students, 
              (SELECT COUNT(*) FROM class_students WHERE class_id = c.id AND status = 'active') AS current_enrollment
       FROM classes c
       WHERE c.id = ?`,
      [class_id]
    );

    if (classRecord.length === 0) {
      return res.status(404).json({ error: 'Class not found' });
    }

    const classData = classRecord[0];

    // Check if class is full
    if (classData.current_enrollment >= classData.total_students) {
      return res.status(400).json({ error: 'Class is full' });
    }

    // Check if already enrolled
    const [existingEnrollment] = await db.promise().query(
      'SELECT id FROM class_students WHERE student_id = ? AND class_id = ? AND status = "active"',
      [user_id, class_id]
    );

    if (existingEnrollment.length > 0) {
      return res.status(400).json({ error: 'Already enrolled in this class' });
    }

    // Check if previously enrolled but inactive
    const [inactiveEnrollment] = await db.promise().query(
      'SELECT id FROM class_students WHERE student_id = ? AND class_id = ? AND status = "inactive"',
      [user_id, class_id]
    );

    if (inactiveEnrollment.length > 0) {
      // Reactivate enrollment
      await db.promise().query(
        'UPDATE class_students SET status = "active" WHERE id = ?',
        [inactiveEnrollment[0].id]
      );
    } else {
      // Create new enrollment
      await db.promise().query(
        'INSERT INTO class_students (student_id, class_id, status) VALUES (?, ?, "active")',
        [user_id, class_id]
      );
    }

    res.status(201).json({ message: 'Successfully enrolled in class' });
  } catch (error) {
    console.error('Enroll student error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Unenroll from Class
 */
app.post('/api/student/classes/:id/unenroll', authenticateStudent, async (req, res) => {
  const { id: class_id } = req.params;
  const { id: user_id } = req.user;
  
  try {
    // Check if enrolled
    const [enrollment] = await db.promise().query(
      'SELECT id FROM class_students WHERE student_id = ? AND class_id = ? AND status = "active"',
      [user_id, class_id]
    );

    if (enrollment.length === 0) {
      return res.status(404).json({ error: 'Not enrolled in this class' });
    }

    // Set enrollment to inactive
    await db.promise().query(
      'UPDATE class_students SET status = "inactive" WHERE id = ?',
      [enrollment[0].id]
    );

    res.json({ message: 'Successfully unenrolled from class' });
  } catch (error) {
    console.error('Unenroll student error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Lecturers Available for Rating
 */
app.get('/api/student/lecturers', authenticateStudent, async (req, res) => {
  const { id: user_id } = req.user;
  
  try {
    // Get lecturers from classes the student is enrolled in
    const [lecturers] = await db.promise().query(
      `SELECT DISTINCT
        u.id,
        u.name,
        u.email,
        u.role,
        s.name AS stream_name,
        f.name AS faculty_name,
        GROUP_CONCAT(DISTINCT co.name) AS courses_taught
       FROM class_students cs
       JOIN classes c ON cs.class_id = c.id
       JOIN users u ON c.lecturer_id = u.id
       JOIN courses co ON c.course_id = co.id
       JOIN programs p ON co.program_id = p.id
       JOIN streams s ON p.stream_id = s.id
       JOIN faculties f ON s.faculty_id = f.id
       WHERE cs.student_id = ? AND cs.status = 'active' AND u.role = 'lecturer'
       GROUP BY u.id, u.name, u.email, u.role, s.name, f.name
       ORDER BY u.name`,
      [user_id]
    );

    res.json(lecturers);
  } catch (error) {
    console.error('Fetch lecturers error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Submit Rating for Lecturer
 */
app.post('/api/student/ratings', authenticateStudent, async (req, res) => {
  const { ratee_id, rating, comment } = req.body;
  const { id: rater_id } = req.user;
  
  try {
    // Validate rating
    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating must be between 1 and 5' });
    }

    // Check if ratee is a lecturer and student has classes with them
    const [validLecturer] = await db.promise().query(
      `SELECT u.id 
       FROM users u
       JOIN classes c ON u.id = c.lecturer_id
       JOIN class_students cs ON c.id = cs.class_id
       WHERE u.id = ? AND u.role = 'lecturer' AND cs.student_id = ? AND cs.status = 'active'
       LIMIT 1`,
      [ratee_id, rater_id]
    );

    if (validLecturer.length === 0) {
      return res.status(400).json({ error: 'Cannot rate this lecturer. You must be enrolled in their class.' });
    }

    // Check if already rated this lecturer
    const [existingRating] = await db.promise().query(
      'SELECT id FROM ratings WHERE rater_id = ? AND ratee_id = ?',
      [rater_id, ratee_id]
    );

    if (existingRating.length > 0) {
      return res.status(400).json({ error: 'You have already rated this lecturer' });
    }

    // Submit rating
    await db.promise().query(
      'INSERT INTO ratings (rater_id, ratee_id, rating, comment) VALUES (?, ?, ?, ?)',
      [rater_id, ratee_id, rating, comment]
    );

    res.status(201).json({ message: 'Rating submitted successfully' });
  } catch (error) {
    console.error('Submit rating error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Student's Submitted Ratings
 */
app.get('/api/student/ratings', authenticateStudent, async (req, res) => {
  const { id: user_id } = req.user;
  
  try {
    const [ratings] = await db.promise().query(
      `SELECT 
        r.id,
        r.ratee_id,
        u.name AS lecturer_name,
        r.rating,
        r.comment,
        r.created_at,
        co.name AS course_name,
        c.name AS class_name
       FROM ratings r
       JOIN users u ON r.ratee_id = u.id
       LEFT JOIN classes c ON u.id = c.lecturer_id
       LEFT JOIN courses co ON c.course_id = co.id
       LEFT JOIN class_students cs ON c.id = cs.class_id AND cs.student_id = ?
       WHERE r.rater_id = ?
       ORDER BY r.created_at DESC`,
      [user_id, user_id]
    );

    res.json(ratings);
  } catch (error) {
    console.error('Fetch student ratings error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Update Student's Rating
 */
app.put('/api/student/ratings/:id', authenticateStudent, async (req, res) => {
  const { id: rating_id } = req.params;
  const { rating, comment } = req.body;
  const { id: user_id } = req.user;
  
  try {
    // Validate rating
    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating must be between 1 and 5' });
    }

    // Check if rating exists and belongs to student
    const [existingRating] = await db.promise().query(
      'SELECT id FROM ratings WHERE id = ? AND rater_id = ?',
      [rating_id, user_id]
    );

    if (existingRating.length === 0) {
      return res.status(404).json({ error: 'Rating not found' });
    }

    // Update rating
    await db.promise().query(
      'UPDATE ratings SET rating = ?, comment = ? WHERE id = ?',
      [rating, comment, rating_id]
    );

    res.json({ message: 'Rating updated successfully' });
  } catch (error) {
    console.error('Update rating error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Delete Student's Rating
 */
app.delete('/api/student/ratings/:id', authenticateStudent, async (req, res) => {
  const { id: rating_id } = req.params;
  const { id: user_id } = req.user;
  
  try {
    // Check if rating exists and belongs to student
    const [existingRating] = await db.promise().query(
      'SELECT id FROM ratings WHERE id = ? AND rater_id = ?',
      [rating_id, user_id]
    );

    if (existingRating.length === 0) {
      return res.status(404).json({ error: 'Rating not found' });
    }

    // Delete rating
    await db.promise().query('DELETE FROM ratings WHERE id = ?', [rating_id]);

    res.json({ message: 'Rating deleted successfully' });
  } catch (error) {
    console.error('Delete rating error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Class Details with Enrollment Status
 */
app.get('/api/student/classes/:id', authenticateStudent, async (req, res) => {
  const { id: class_id } = req.params;
  const { id: user_id } = req.user;
  
  try {
    const [classDetails] = await db.promise().query(
      `SELECT 
        c.id,
        c.name AS class_name,
        co.name AS course_name,
        co.code AS course_code,
        co.description AS course_description,
        u.name AS lecturer_name,
        u.email AS lecturer_email,
        c.venue,
        c.scheduled_time,
        c.total_students,
        (SELECT COUNT(*) FROM class_students WHERE class_id = c.id AND status = 'active') AS enrolled_students,
        IF(cs.id IS NOT NULL, true, false) AS is_enrolled,
        cs.status AS enrollment_status
       FROM classes c
       JOIN courses co ON c.course_id = co.id
       JOIN users u ON c.lecturer_id = u.id
       LEFT JOIN class_students cs ON c.id = cs.class_id AND cs.student_id = ?
       WHERE c.id = ?`,
      [user_id, class_id]
    );

    if (classDetails.length === 0) {
      return res.status(404).json({ error: 'Class not found' });
    }

    res.json(classDetails[0]);
  } catch (error) {
    console.error('Fetch class details error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// STUDENT MONITORING ENDPOINTS
// ==============================================

/**
 * Get Student Attendance Monitoring Data - CORRECTED VERSION
 */
app.get('/api/student/monitoring/attendance', authenticateStudent, async (req, res) => {
  const { id: user_id } = req.user;
  
  try {
    console.log('Fetching attendance for student:', user_id);
    
    const [attendance] = await db.promise().query(
      `SELECT 
        a.date,
        c.name AS class_name,
        co.name AS course_name,
        co.code AS course_code,
        u.name AS lecturer_name,
        a.present AS student_present,
        c.id AS class_id,
        DATE_FORMAT(a.date, '%Y-%m-%d') AS formatted_date
       FROM attendance a
       JOIN classes c ON a.class_id = c.id
       JOIN courses co ON c.course_id = co.id
       JOIN users u ON c.lecturer_id = u.id
       WHERE a.student_id = ?
       ORDER BY a.date DESC
       LIMIT 50`,
      [user_id]
    );

    console.log('Attendance data found:', attendance.length, 'records');
    
    res.json(attendance);
  } catch (error) {
    console.error('Fetch student attendance error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Student Class Reports
 */
app.get('/api/student/monitoring/reports', authenticateStudent, async (req, res) => {
  const { id: user_id } = req.user;
  
  try {
    const [reports] = await db.promise().query(
      `SELECT 
        r.id,
        r.class_id,
        c.name AS class_name,
        co.name AS course_name,
        co.code AS course_code,
        u.name AS lecturer_name,
        r.week,
        r.date,
        r.topic,
        r.outcomes,
        r.recommendations,
        r.actual_students,
        r.total_students,
        fb.feedback
       FROM class_students cs
       JOIN classes c ON cs.class_id = c.id
       JOIN courses co ON c.course_id = co.id
       JOIN users u ON c.lecturer_id = u.id
       JOIN reports r ON c.id = r.class_id
       LEFT JOIN feedback fb ON r.id = fb.report_id
       WHERE cs.student_id = ? AND cs.status = 'active'
       ORDER BY r.date DESC, r.week DESC`,
      [user_id]
    );

    res.json(reports);
  } catch (error) {
    console.error('Fetch student reports error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Student Progress Statistics - CORRECTED VERSION
 */
app.get('/api/student/monitoring/stats', authenticateStudent, async (req, res) => {
  const { id: user_id } = req.user;
  
  try {
    console.log('Fetching stats for student:', user_id);

    // Get total classes enrolled
    const [totalClasses] = await db.promise().query(
      'SELECT COUNT(*) as total FROM class_students WHERE student_id = ? AND status = "active"',
      [user_id]
    );

    // Get total attendance records and present count
    const [attendanceStats] = await db.promise().query(
      `SELECT 
        COUNT(*) as total_records,
        SUM(CASE WHEN present = true THEN 1 ELSE 0 END) as present_records
       FROM attendance 
       WHERE student_id = ?`,
      [user_id]
    );

    // Calculate attendance percentage based on actual attendance records
    let overallAttendance = 0;
    if (attendanceStats[0]?.total_records > 0) {
      overallAttendance = Math.round(
        (attendanceStats[0].present_records / attendanceStats[0].total_records) * 100
      );
    }

    // Get classes with attendance (distinct class dates attended)
    const [attendedClasses] = await db.promise().query(
      `SELECT COUNT(DISTINCT CONCAT(class_id, '-', date)) as attended_sessions
       FROM attendance 
       WHERE student_id = ? AND present = true`,
      [user_id]
    );

    // Get average lecturer rating from student's submitted ratings
    const [ratingStats] = await db.promise().query(
      `SELECT AVG(rating) as avg_rating 
       FROM ratings 
       WHERE rater_id = ?`,
      [user_id]
    );

    const avgRating = ratingStats[0]?.avg_rating ? parseFloat(ratingStats[0].avg_rating).toFixed(1) : 0;

    const stats = {
      overallAttendance: overallAttendance,
      classesAttended: attendedClasses[0]?.attended_sessions || 0,
      totalClasses: totalClasses[0]?.total || 0,
      averageRating: avgRating
    };

    console.log('Student stats:', stats);
    res.json(stats);
  } catch (error) {
    console.error('Fetch student stats error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// PROGRAM LEADER LECTURER ENDPOINTS
// ==============================================

/**
 * Get Lecturers for Program Leader (Only lecturers in their program)
 */
app.get('/api/pl/lecturers', authenticatePL, async (req, res) => {
  const { program_id } = req.user;
  
  try {
    const [lecturers] = await db.promise().query(
      `SELECT DISTINCT u.id, u.name, u.email, u.role
       FROM users u
       JOIN classes c ON u.id = c.lecturer_id
       JOIN courses co ON c.course_id = co.id
       WHERE u.role = 'lecturer' AND co.program_id = ?
       ORDER BY u.name`,
      [program_id]
    );
    
    res.json(lecturers);
  } catch (error) {
    console.error('Fetch PL lecturers error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// PRL TO PROGRAM LEADER REPORTING ENDPOINTS
// ==============================================

/**
 * PRL submits report to Program Leader
 */
app.post('/api/prl/reports-to-pl', authenticatePRL, async (req, res) => {
  const { program_id, title, content, recommendations, priority } = req.body;
  const { id: prl_id, stream_id } = req.user;

  try {
    // Verify program belongs to PRL's stream
    const [program] = await db.promise().query(
      'SELECT id FROM programs WHERE id = ? AND stream_id = ?',
      [program_id, stream_id]
    );

    if (program.length === 0) {
      return res.status(404).json({ error: 'Program not found in your stream' });
    }

    // Create PRL report
    const [result] = await db.promise().query(
      `INSERT INTO prl_reports 
       (prl_id, program_id, title, content, recommendations, priority, status) 
       VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
      [prl_id, program_id, title, content, recommendations, priority]
    );

    res.status(201).json({ 
      message: 'Report submitted successfully to Program Leader',
      reportId: result.insertId 
    });
  } catch (error) {
    console.error('PRL report submission error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * PRL views their submitted reports to PL
 */
app.get('/api/prl/my-reports-to-pl', authenticatePRL, async (req, res) => {
  const { id: prl_id } = req.user;

  try {
    const [reports] = await db.promise().query(
      `SELECT 
        pr.id,
        pr.title,
        pr.content,
        pr.recommendations,
        pr.priority,
        pr.status,
        pr.created_at,
        pr.pl_feedback,
        pr.feedback_date,
        p.name AS program_name,
        pl.name AS pl_name
       FROM prl_reports pr
       JOIN programs p ON pr.program_id = p.id
       LEFT JOIN users pl ON p.pl_id = pl.id
       WHERE pr.prl_id = ?
       ORDER BY pr.created_at DESC`,
      [prl_id]
    );

    res.json(reports);
  } catch (error) {
    console.error('Fetch PRL reports error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get PRL Reports for Program Leader
 */
app.get('/api/pl/prl-reports', authenticatePL, async (req, res) => {
  const { program_id } = req.user;

  try {
    const [reports] = await db.promise().query(
      `SELECT 
        pr.id,
        pr.title,
        pr.content,
        pr.recommendations,
        pr.priority,
        pr.status,
        pr.created_at,
        pr.pl_feedback,
        pr.feedback_date,
        p.name AS program_name,
        u.name AS prl_name,
        u.email AS prl_email
       FROM prl_reports pr
       JOIN programs p ON pr.program_id = p.id
       JOIN users u ON pr.prl_id = u.id
       WHERE p.id = ?
       ORDER BY 
         CASE pr.priority 
           WHEN 'urgent' THEN 1
           WHEN 'high' THEN 2
           WHEN 'medium' THEN 3
           WHEN 'low' THEN 4
         END,
         pr.created_at DESC`,
      [program_id]
    );

    res.json(reports);
  } catch (error) {
    console.error('Fetch PL PRL reports error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Program Leader provides feedback on PRL report
 */
app.post('/api/pl/reports/:id/feedback', authenticatePL, async (req, res) => {
  const { id } = req.params;
  const { feedback } = req.body;
  const { program_id } = req.user;

  try {
    // Verify the report belongs to PL's program
    const [report] = await db.promise().query(
      `SELECT pr.id 
       FROM prl_reports pr
       JOIN programs p ON pr.program_id = p.id
       WHERE pr.id = ? AND p.id = ?`,
      [id, program_id]
    );

    if (report.length === 0) {
      return res.status(404).json({ error: 'Report not found in your program' });
    }

    // Update report with PL feedback
    await db.promise().query(
      `UPDATE prl_reports 
       SET pl_feedback = ?, feedback_date = NOW(), status = 'reviewed'
       WHERE id = ?`,
      [feedback, id]
    );

    res.json({ message: 'Feedback submitted successfully' });
  } catch (error) {
    console.error('PL feedback submission error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get single PRL report details for PL
 */
app.get('/api/pl/reports/:id', authenticatePL, async (req, res) => {
  const { id } = req.params;
  const { program_id } = req.user;

  try {
    const [reports] = await db.promise().query(
      `SELECT 
        pr.id,
        pr.title,
        pr.content,
        pr.recommendations,
        pr.priority,
        pr.status,
        pr.created_at,
        pr.pl_feedback,
        pr.feedback_date,
        p.name AS program_name,
        u.name AS prl_name,
        u.email AS prl_email
       FROM prl_reports pr
       JOIN programs p ON pr.program_id = p.id
       JOIN users u ON pr.prl_id = u.id
       WHERE pr.id = ? AND p.id = ?`,
      [id, program_id]
    );

    if (reports.length === 0) {
      return res.status(404).json({ error: 'Report not found' });
    }

    res.json(reports[0]);
  } catch (error) {
    console.error('Fetch PL report details error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// HEALTH CHECK AND SERVER INITIALIZATION
// ==============================================

/**
 * Health Check Endpoint
 */
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    database: db.state === 'connected' ? 'Connected' : 'Disconnected',
    environment: process.env.NODE_ENV || 'development'
  });
});

/**
 * Start Express Server
 */
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`LUCT Management System API is ready!`);
  console.log(`Access the API at: http://localhost:${PORT}`);
});