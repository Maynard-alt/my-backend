const express = require('express');
const db = require('./database');
const jwt = require('jsonwebtoken');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'demo_bank_secret_key';

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

// Get user transactions
router.get('/', verifyToken, (req, res) => {
  db.all(
    'SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC',
    [req.user.id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(rows);
    }
  );
});

// Create a new transaction
router.post('/', verifyToken, (req, res) => {
  const { type, amount, recipient_name, recipient_account, description } = req.body;

  // Check if account is frozen
  db.get('SELECT is_frozen FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (user.is_frozen) {
      return res.status(400).json({ error: 'This account has been frozen temporarily' });
    }

    // Generate unique ID for transaction
    const uniqueId = 'TXN' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase();

    // Generate OTP (for demo, we'll use a simple 6-digit code)
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Insert transaction with OTP
    db.run(
      `INSERT INTO transactions 
      (user_id, type, amount, recipient_name, recipient_account, description, unique_id, otp) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.user.id, type, amount, recipient_name, recipient_account, description, uniqueId, otp],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to create transaction' });
        }

        // In a real application, you would send this OTP to the user's email/phone
        // For demo, we'll just return it in the response
        res.status(201).json({
          message: 'Transaction created successfully. OTP required for verification.',
          transactionId: this.lastID,
          uniqueId: uniqueId,
          otp: otp // This would not be included in production - only for demo
        });
      }
    );
  });
});

// Verify OTP for transaction
router.post('/:id/verify-otp', verifyToken, (req, res) => {
  const transactionId = req.params.id;
  const { otp } = req.body;

  // First get the transaction to check the OTP
  db.get('SELECT * FROM transactions WHERE id = ? AND user_id = ?', [transactionId, req.user.id], (err, transaction) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    // Check if OTP matches
    if (transaction.otp !== otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    // Update transaction as OTP verified
    db.run(
      'UPDATE transactions SET otp_verified = 1 WHERE id = ?',
      [transactionId],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to verify OTP' });
        }

        res.json({ 
          message: 'OTP verified successfully. Transaction is now pending admin approval.',
          transactionId: transactionId
        });
      }
    );
  });
});

// Get transaction receipt
router.get('/:id/receipt', verifyToken, (req, res) => {
  const transactionId = req.params.id;

  db.get(
    `SELECT t.*, u.full_name as sender_name 
     FROM transactions t 
     JOIN users u ON t.user_id = u.id 
     WHERE t.id = ? AND t.user_id = ?`,
    [transactionId, req.user.id],
    (err, transaction) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (!transaction) {
        return res.status(404).json({ error: 'Transaction not found' });
      }

      res.json(transaction);
    }
  );
});

// Request a loan
router.post('/loan', verifyToken, (req, res) => {
  const { amount, term } = req.body;

  // Check if account is frozen
  db.get('SELECT is_frozen FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (user.is_frozen) {
      return res.status(400).json({ error: 'This account has been frozen temporarily' });
    }

    // Insert loan request
    db.run(
      'INSERT INTO loans (user_id, amount, term) VALUES (?, ?, ?)',
      [req.user.id, amount, term],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to request loan' });
        }

        res.status(201).json({
          message: 'Loan request submitted successfully. Waiting for admin approval.',
          loanId: this.lastID
        });
      }
    );
  });
});

// Get user loans
router.get('/loan', verifyToken, (req, res) => {
  db.all(
    'SELECT * FROM loans WHERE user_id = ? ORDER BY created_at DESC',
    [req.user.id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(rows);
    }
  );
});

// Create support ticket
router.post('/support', verifyToken, (req, res) => {
  const { subject, message } = req.body;

  db.run(
    'INSERT INTO support_tickets (user_id, subject, message) VALUES (?, ?, ?)',
    [req.user.id, subject, message],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to create support ticket' });
      }

      res.status(201).json({
        message: 'Support ticket created successfully.',
        ticketId: this.lastID
      });
    }
  );
});

// Get user support tickets
router.get('/support', verifyToken, (req, res) => {
  db.all(
    'SELECT * FROM support_tickets WHERE user_id = ? ORDER BY created_at DESC',
    [req.user.id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(rows);
    }
  );
});

// Add response to support ticket - NEW ENDPOINT
router.post('/support/:ticketId/response', verifyToken, (req, res) => {
  const { ticketId } = req.params;
  const { message } = req.body;

  // Verify the ticket exists and belongs to the user
  db.get('SELECT * FROM support_tickets WHERE id = ? AND user_id = ?', [ticketId, req.user.id], (err, ticket) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    // Add the response (for demo, we'll update the existing message)
    // In a real app, you'd have a separate table for ticket responses
    const updatedMessage = ticket.message + '\n\n--- User Response ---\n' + message;
    
    db.run(
    'UPDATE support_tickets SET message = ? WHERE id = ?',
    [updatedMessage, ticketId],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to add response' });
        }

        res.json({ 
          success: true, 
          message: 'Response added successfully' 
        });
      }
    );
  });
});

// When creating transactions, amounts should be negative for outgoing transfers
router.post('/', verifyToken, (req, res) => {
    const { type, amount, recipient_name, recipient_account, description } = req.body;

    // Convert amount to negative for withdrawals and transfers
    const processedAmount = (type === 'withdrawal' || type === 'transfer') ? 
        -Math.abs(amount) : Math.abs(amount);

    // Use processedAmount instead of amount in the database insert
});

module.exports = router;