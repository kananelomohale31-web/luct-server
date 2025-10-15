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

// Configure CORS to allow requests from frontend
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));

// Parse JSON request bodies
app.use(express.json());

// ==============================================
// DATABASE CONFIGURATION
// ==============================================

// Create MySQL database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', // Should be stored in environment variables in production
  database: 'luct_db', // LUCT Management System database
});

// Connect to database
db.connect((err) => {
  if (err) throw err;
  console.log('Connected to database');
});

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
 * FIXED: Removed 'description' column that doesn't exist in database
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
      query = `SELECT s.id, s.name, s.faculty_id, f.name AS faculty_name
               FROM streams s
               LEFT JOIN faculties f ON s.faculty_id = f.id
               WHERE s.faculty_id = ?
               ORDER BY s.name`;
      params = [faculty_id];
    } else {
      query = `SELECT s.id, s.name, s.faculty_id, f.name AS faculty_name
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
      res.json(results);
    });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({ error: 'Invalid token', details: error.message });
  }
});

/**
 * Create Stream (Admin Only)
 */
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
 * FIXED: Removed 'description' column that doesn't exist in database
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
      query = `SELECT p.id, p.name, p.stream_id, s.name AS stream_name
               FROM programs p
               LEFT JOIN streams s ON p.stream_id = s.id
               WHERE p.stream_id = ?
               ORDER BY p.name`;
      params = [stream_id];
    } else {
      query = `SELECT p.id, p.name, p.stream_id, s.name AS stream_name
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

// ... (rest of your existing endpoints remain the same)
// I'm keeping the rest of your endpoints as they were since they're working

// ==============================================
// STUDENT PROFILE & DASHBOARD ENDPOINTS

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
        st.name AS stream_name, 
        f.name AS faculty_name
       FROM users u
       LEFT JOIN programs p ON u.program_id = p.id
       LEFT JOIN streams st ON p.stream_id = st.id
       LEFT JOIN faculties f ON st.faculty_id = f.id
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
        st.name AS stream_name,
        f.name AS faculty_name
       FROM users u
       LEFT JOIN programs p ON u.program_id = p.id
       LEFT JOIN streams st ON p.stream_id = st.id
       LEFT JOIN faculties f ON st.faculty_id = f.id
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
       WHERE student_id = ?`,
      [user_id]
    );

    // Get assignments count (placeholder for now)
    const assignmentCount = 0;

    // Get announcements count (placeholder for now)
    const announcementCount = 0;

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
        classes: classes[0].class_count || 0,
        assignments: assignmentCount,
        announcements: announcementCount
      }
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Unassigned Students (Admin Only)
 */
app.get('/api/admin/unassigned-students', authenticateAdmin, async (req, res) => {
  try {
    const [unassigned] = await db.promise().query(
      `SELECT 
        u.id,
        u.name,
        u.email,
        u.program_id,
        p.name AS program_name
       FROM users u
       LEFT JOIN programs p ON u.program_id = p.id
       WHERE u.role = 'student' AND u.student_id IS NULL
       ORDER BY u.name`
    );
    
    res.json(unassigned);
  } catch (error) {
    console.error('Fetch unassigned students error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Student Classes
 */
app.get('/api/student/classes', authenticateStudent, async (req, res) => {
  const { id: user_id } = req.user;
  
  try {
    const [classes] = await db.promise().query(
      `SELECT 
        c.id,
        c.name,
        c.code,
        c.schedule,
        c.room,
        l.name as lecturer_name,
        l.email as lecturer_email
       FROM classes c
       JOIN class_students cs ON c.id = cs.class_id
       JOIN users l ON c.lecturer_id = l.id
       WHERE cs.student_id = ?
       ORDER BY c.name`,
      [user_id]
    );
    
    res.json(classes);
  } catch (error) {
    console.error('Fetch student classes error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// GENERAL DASHBOARD ENDPOINTS
// ==============================================

/**
 * Get Faculty by ID
 */
app.get('/api/faculties/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [faculties] = await db.promise().query('SELECT * FROM faculties WHERE id = ?', [id]);
    if (faculties.length === 0) return res.status(404).json({ error: 'Faculty not found' });
    res.json(faculties[0]);
  } catch (error) {
    console.error('Fetch faculty error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Stream by ID
 */
app.get('/api/streams/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [streams] = await db.promise().query(
      'SELECT s.id, s.name, s.faculty_id, f.name AS faculty_name, s.prl_id, u.name AS prl_name ' +
      'FROM streams s LEFT JOIN faculties f ON s.faculty_id = f.id LEFT JOIN users u ON s.prl_id = u.id ' +
      'WHERE s.id = ?',
      [id]
    );
    if (streams.length === 0) return res.status(404).json({ error: 'Stream not found' });
    res.json(streams[0]);
  } catch (error) {
    console.error('Fetch stream error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

/**
 * Get Program by ID
 */
app.get('/api/programs/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [programs] = await db.promise().query(
      'SELECT p.id, p.name, p.stream_id, s.name AS stream_name, s.faculty_id, f.name AS faculty_name, p.pl_id, u.name AS pl_name ' +
      'FROM programs p LEFT JOIN streams s ON p.stream_id = s.id ' +
      'LEFT JOIN faculties f ON s.faculty_id = f.id LEFT JOIN users u ON p.pl_id = u.id ' +
      'WHERE p.id = ?',
      [id]
    );
    if (programs.length === 0) return res.status(404).json({ error: 'Program not found' });
    res.json(programs[0]);
  } catch (error) {
    console.error('Fetch program error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==============================================
// SERVER INITIALIZATION
// ==============================================

/**
 * Start Express Server
 */

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

// ==============================================
// SERVER INITIALIZATION
// ==============================================

/**
 * Start Express Server
 */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`LUCT Management System API is ready!`);
  console.log(`Access the API at: http://localhost:${PORT}`);
});