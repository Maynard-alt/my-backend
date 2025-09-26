const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./database');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'demo_bank_secret_key';

// Register endpoint - FIXED
router.post('/register', async (req, res) => {
  const { full_name, phone_number, email, date_of_birth, password } = req.body;

  // Validate required fields
  if (!full_name || !phone_number || !email || !date_of_birth || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    // Check if user already exists
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (row) {
        return res.status(400).json({ error: 'User already exists' });
      }

      // Hash password - FIXED: Added proper error handling
      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        // Add this to auth.js
router.get('/verify-token', verifyToken, (req, res) => {
    res.json({
        valid: true,
        isAdmin: req.user.isAdmin || false,
        user: req.user
    });
});

        // Insert new user
        db.run(
          'INSERT INTO users (full_name, phone_number, email, date_of_birth, password) VALUES (?, ?, ?, ?, ?)',
          [full_name, phone_number, email, date_of_birth, hashedPassword],
          function(err) {
            if (err) {
              return res.status(500).json({ error: 'Failed to create user' });
            }
            res.status(201).json({ message: 'Registration successful. Waiting for admin approval.' });
          }
        );
      } catch (hashError) {
        return res.status(500).json({ error: 'Failed to hash password' });
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login endpoint
router.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Validate required fields
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // Find user
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check if account is approved
    if (user.status !== 'approved') {
      return res.status(400).json({ error: 'Account pending approval' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        full_name: user.full_name,
        email: user.email,
        balance: user.balance
      }
    });
  });
});

// Admin login endpoint
router.post('/admin/login', (req, res) => {
  const { username, password } = req.body;

  // Validate required fields
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Find admin
  db.get('SELECT * FROM admins WHERE username = ?', [username], async (err, admin) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!admin) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { id: admin.id, username: admin.username, isAdmin: true },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      message: 'Admin login successful',
      token,
      admin: {
        id: admin.id,
        username: admin.username
      }
    });
  });
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid token' });
  }
};

// Get user profile
router.get('/profile', verifyToken, (req, res) => {
  db.get('SELECT id, full_name, phone_number, email, date_of_birth, balance, is_frozen FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  });
});

// Update user profile
router.put('/profile', verifyToken, async (req, res) => {
  const { full_name, phone_number, date_of_birth } = req.body;

  try {
    db.run(
      'UPDATE users SET full_name = ?, phone_number = ?, date_of_birth = ? WHERE id = ?',
      [full_name, phone_number, date_of_birth, req.user.id],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to update profile' });
        }
        res.json({ message: 'Profile updated successfully' });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Change password
router.put('/change-password', verifyToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  // Validate required fields
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required' });
  }

  try {
    // Get user
    db.get('SELECT password FROM users WHERE id = ?', [req.user.id], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      // Check current password
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password
      db.run(
        'UPDATE users SET password = ? WHERE id = ?',
        [hashedPassword, req.user.id],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to change password' });
          }
          res.json({ message: 'Password changed successfully' });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;