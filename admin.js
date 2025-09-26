const express = require('express');
const bcrypt = require('bcryptjs');
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

// Middleware to verify admin - MUST BE DEFINED BEFORE USE
const verifyAdmin = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Access denied. Admin only.' });
  }
  next();
};

// ========== EXISTING ROUTES (KEEP THESE) ==========

// Get all pending users
router.get('/users/pending', verifyToken, verifyAdmin, (req, res) => {
  db.all('SELECT id, full_name, phone_number, email, date_of_birth, created_at FROM users WHERE status = "pending"', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Approve user
router.put('/users/:id/approve', verifyToken, verifyAdmin, (req, res) => {
  const userId = req.params.id;

  db.run('UPDATE users SET status = "approved" WHERE id = ?', [userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to approve user' });
    }

    // Log admin activity
    db.run(
      'INSERT INTO admin_activities (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, 'approve', 'user', userId, 'User account approved'],
      function(err) {
        if (err) {
          console.error('Failed to log admin activity:', err);
        }
      }
    );

    res.json({ message: 'User approved successfully' });
  });
});

// Reject user
router.delete('/users/:id/reject', verifyToken, verifyAdmin, (req, res) => {
  const userId = req.params.id;

  db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to reject user' });
    }

    // Log admin activity
    db.run(
      'INSERT INTO admin_activities (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, 'reject', 'user', userId, 'User registration rejected'],
      function(err) {
        if (err) {
          console.error('Failed to log admin activity:', err);
        }
      }
    );

    res.json({ message: 'User rejected successfully' });
  });
});

// Get all users
router.get('/users', verifyToken, verifyAdmin, (req, res) => {
  db.all('SELECT id, full_name, phone_number, email, date_of_birth, status, is_frozen, balance, created_at FROM users', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Freeze/unfreeze user account
router.put('/users/:id/freeze', verifyToken, verifyAdmin, (req, res) => {
  const userId = req.params.id;
  const { is_frozen } = req.body;

  db.run('UPDATE users SET is_frozen = ? WHERE id = ?', [is_frozen ? 1 : 0, userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to update user status' });
    }

    // Log admin activity
    const action = is_frozen ? 'freeze' : 'unfreeze';
    db.run(
      'INSERT INTO admin_activities (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, action, 'user', userId, `User account ${action}d`],
      function(err) {
        if (err) {
          console.error('Failed to log admin activity:', err);
        }
      }
    );

    res.json({ message: `User account ${is_frozen ? 'frozen' : 'unfrozen'} successfully` });
  });
});

// Get all pending transactions
router.get('/transactions/pending', verifyToken, verifyAdmin, (req, res) => {
  db.all(`
    SELECT t.*, u.full_name as user_name 
    FROM transactions t 
    JOIN users u ON t.user_id = u.id 
    WHERE t.status = 'pending'
  `, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Approve transaction
router.put('/transactions/:id/approve', verifyToken, verifyAdmin, (req, res) => {
  const transactionId = req.params.id;

  // First get transaction details
  db.get('SELECT * FROM transactions WHERE id = ?', [transactionId], (err, transaction) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    // Update transaction status
    db.run('UPDATE transactions SET status = "approved" WHERE id = ?', [transactionId], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to approve transaction' });
      }

      // If it's a withdrawal, update user balance
      if (transaction.type === 'withdrawal') {
        db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [transaction.amount, transaction.user_id], function(err) {
          if (err) {
            console.error('Failed to update user balance:', err);
          }
        });
      }

      // Log admin activity
      db.run(
        'INSERT INTO admin_activities (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
        [req.user.id, 'approve', 'transaction', transactionId, `Transaction approved: ${transaction.type} of $${transaction.amount}`],
        function(err) {
          if (err) {
            console.error('Failed to log admin activity:', err);
          }
        }
      );

      res.json({ message: 'Transaction approved successfully' });
    });
  });
});

// Reject transaction
router.put('/transactions/:id/reject', verifyToken, verifyAdmin, (req, res) => {
  const transactionId = req.params.id;

  db.run('UPDATE transactions SET status = "rejected" WHERE id = ?', [transactionId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to reject transaction' });
    }

    // Log admin activity
    db.run(
      'INSERT INTO admin_activities (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, 'reject', 'transaction', transactionId, 'Transaction rejected'],
      function(err) {
        if (err) {
          console.error('Failed to log admin activity:', err);
        }
      }
    );

    res.json({ message: 'Transaction rejected successfully' });
  });
});

// Get all pending loans
router.get('/loans/pending', verifyToken, verifyAdmin, (req, res) => {
  db.all(`
    SELECT l.*, u.full_name as user_name 
    FROM loans l 
    JOIN users u ON l.user_id = u.id 
    WHERE l.status = 'pending'
  `, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Approve loan
router.put('/loans/:id/approve', verifyToken, verifyAdmin, (req, res) => {
  const loanId = req.params.id;

  // First get loan details
  db.get('SELECT * FROM loans WHERE id = ?', [loanId], (err, loan) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!loan) {
      return res.status(404).json({ error: 'Loan not found' });
    }

    // Update loan status and add to user balance
    db.run('UPDATE loans SET status = "approved" WHERE id = ?', [loanId], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to approve loan' });
      }

      // Add loan amount to user balance
      db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [loan.amount, loan.user_id], function(err) {
        if (err) {
          console.error('Failed to update user balance:', err);
        }
      });

      // Log admin activity
      db.run(
        'INSERT INTO admin_activities (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
        [req.user.id, 'approve', 'loan', loanId, `Loan approved: $${loan.amount} for ${loan.term} months`],
        function(err) {
          if (err) {
            console.error('Failed to log admin activity:', err);
          }
        }
      );

      res.json({ message: 'Loan approved successfully' });
    });
  });
});

// Reject loan
router.put('/loans/:id/reject', verifyToken, verifyAdmin, (req, res) => {
  const loanId = req.params.id;

  db.run('UPDATE loans SET status = "rejected" WHERE id = ?', [loanId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to reject loan' });
    }

    // Log admin activity
    db.run(
      'INSERT INTO admin_activities (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, 'reject', 'loan', loanId, 'Loan rejected'],
      function(err) {
        if (err) {
          console.error('Failed to log admin activity:', err);
        }
      }
    );

    res.json({ message: 'Loan rejected successfully' });
  });
});

// ========== SUPPORT TICKETS ROUTES ==========

// Get all support tickets
router.get('/support-tickets', verifyToken, verifyAdmin, (req, res) => {
  db.all(`
    SELECT s.*, u.full_name as user_name 
    FROM support_tickets s 
    JOIN users u ON s.user_id = u.id 
    ORDER BY s.created_at DESC
  `, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Get specific ticket details
router.get('/support-tickets/:id', verifyToken, verifyAdmin, (req, res) => {
  const ticketId = req.params.id;
  
  db.get(`
    SELECT s.*, u.full_name as user_name 
    FROM support_tickets s 
    JOIN users u ON s.user_id = u.id 
    WHERE s.id = ?
  `, [ticketId], (err, ticket) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    res.json(ticket);
  });
});

// Get ticket conversation/messages
router.get('/support-tickets/:id/conversation', verifyToken, verifyAdmin, (req, res) => {
  const ticketId = req.params.id;
  
  // First check if ticket exists
  db.get('SELECT * FROM support_tickets WHERE id = ?', [ticketId], (err, ticket) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    // For now, return the main ticket as the first message + admin response if exists
    const messages = [];
    
    // Add the original ticket as first message
    messages.push({
      id: 1,
      message: ticket.message || ticket.subject,
      sender_type: 'user',
      user_name: 'User', // We'll get the actual name in the next query
      created_at: ticket.created_at
    });
    
    // Add admin response if exists
    if (ticket.admin_response) {
      messages.push({
        id: 2,
        message: ticket.admin_response,
        sender_type: 'admin',
        user_name: 'Support Agent',
        created_at: ticket.updated_at || ticket.created_at
      });
    }
    
    // Now get the user name properly
    db.get(`
      SELECT u.full_name as user_name 
      FROM support_tickets s 
      JOIN users u ON s.user_id = u.id 
      WHERE s.id = ?
    `, [ticketId], (err, result) => {
      if (!err && result) {
        // Update the user name in the first message
        if (messages.length > 0) {
          messages[0].user_name = result.user_name;
        }
      }
      
      res.json(messages);
    });
  });
});

// Respond to support ticket
router.put('/support-tickets/:id/respond', verifyToken, verifyAdmin, (req, res) => {
  const ticketId = req.params.id;
  const { response, status } = req.body;

  db.run(
    'UPDATE support_tickets SET admin_response = ?, status = ? WHERE id = ?',
    [response, status, ticketId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to respond to ticket' });
      }

      // Log admin activity
      db.run(
        'INSERT INTO admin_activities (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
        [req.user.id, 'respond', 'support_ticket', ticketId, `Responded to support ticket: ${response.substring(0, 50)}...`],
        function(err) {
          if (err) {
            console.error('Failed to log admin activity:', err);
          }
        }
      );

      res.json({ message: 'Response sent successfully' });
    }
  );
});

// ========== ADMIN ACTIVITIES ==========

// Get admin activities log
router.get('/activities', verifyToken, verifyAdmin, (req, res) => {
  db.all(`
    SELECT a.*, ad.username as admin_name 
    FROM admin_activities a 
    JOIN admins ad ON a.admin_id = ad.id 
    ORDER BY a.created_at DESC
    LIMIT 100
  `, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// ========== ADMIN SUPER POWER ENDPOINTS ==========

// Set user balance directly
router.put('/users/:id/balance', verifyToken, verifyAdmin, (req, res) => {
  const userId = req.params.id;
  const { balance } = req.body;

  if (balance === undefined || balance === null) {
    return res.status(400).json({ error: 'Balance is required' });
  }

  db.run('UPDATE users SET balance = ? WHERE id = ?', [balance, userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to update balance' });
    }

    // Log admin activity
    db.run(
      'INSERT INTO admin_activities (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, 'update_balance', 'user', userId, `Set balance to $${balance}`],
      function(err) {
        if (err) {
          console.error('Failed to log admin activity:', err);
        }
      }
    );

    res.json({ message: 'Balance updated successfully', newBalance: balance });
  });
});

// Get user balance
router.get('/users/:id/balance', verifyToken, verifyAdmin, (req, res) => {
  const userId = req.params.id;

  db.get('SELECT balance FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!row) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ balance: row.balance });
  });
});

// Create transaction for any user (bypasses OTP and pending state)
router.post('/transactions/create', verifyToken, verifyAdmin, (req, res) => {
  const { user_id, type, amount, recipient_name, recipient_account, description, status } = req.body;

  // Generate unique ID for transaction
  const uniqueId = 'ADM' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase();

  // Insert transaction (bypass normal flow)
  db.run(
    `INSERT INTO transactions 
    (user_id, type, amount, recipient_name, recipient_account, description, unique_id, otp_verified, status) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [user_id, type, amount, recipient_name, recipient_account, description, uniqueId, 1, status || 'approved'],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to create transaction' });
      }

      // Update user balance if transaction is approved
      if (status === 'approved' || status === undefined) {
        if (type === 'withdrawal') {
          db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, user_id]);
        } else if (type === 'deposit' || type === 'loan') {
          db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, user_id]);
        }
      }

      // Log admin activity
      db.run(
        'INSERT INTO admin_activities (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
        [req.user.id, 'create_transaction', 'transaction', this.lastID, `Created ${type} transaction: $${amount}`],
        function(err) {
          if (err) {
            console.error('Failed to log admin activity:', err);
          }
        }
      );

      res.status(201).json({
        message: 'Transaction created successfully',
        transactionId: this.lastID,
        uniqueId: uniqueId
      });
    }
  );
});

// Edit existing transaction
router.put('/transactions/:id', verifyToken, verifyAdmin, (req, res) => {
  const transactionId = req.params.id;
  const { type, amount, recipient_name, recipient_account, description, status } = req.body;

  // First get the original transaction
  db.get('SELECT * FROM transactions WHERE id = ?', [transactionId], (err, transaction) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    // Update transaction
    db.run(
      `UPDATE transactions SET 
      type = ?, amount = ?, recipient_name = ?, recipient_account = ?, description = ?, status = ?
      WHERE id = ?`,
      [type, amount, recipient_name, recipient_account, description, status, transactionId],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to update transaction' });
        }

        // Log admin activity
        db.run(
          'INSERT INTO admin_activities (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
          [req.user.id, 'edit_transaction', 'transaction', transactionId, `Edited transaction: ${type} $${amount}`],
          function(err) {
            if (err) {
              console.error('Failed to log admin activity:', err);
            }
          }
        );

        res.json({ message: 'Transaction updated successfully' });
      }
    );
  });
});

// Delete transaction
router.delete('/transactions/:id', verifyToken, verifyAdmin, (req, res) => {
  const transactionId = req.params.id;

  db.run('DELETE FROM transactions WHERE id = ?', [transactionId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete transaction' });
    }

    // Log admin activity
    db.run(
      'INSERT INTO admin_activities (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, 'delete_transaction', 'transaction', transactionId, 'Deleted transaction'],
      function(err) {
        if (err) {
          console.error('Failed to log admin activity:', err);
        }
      }
    );

    res.json({ message: 'Transaction deleted successfully' });
  });
});

// Get all transactions with filters
router.get('/transactions/all', verifyToken, verifyAdmin, (req, res) => {
  const { user_id, type, status, start_date, end_date } = req.query;
  
  let query = `
    SELECT t.*, u.full_name as user_name 
    FROM transactions t 
    JOIN users u ON t.user_id = u.id 
    WHERE 1=1
  `;
  let params = [];

  if (user_id) {
    query += ' AND t.user_id = ?';
    params.push(user_id);
  }
  if (type) {
    query += ' AND t.type = ?';
    params.push(type);
  }
  if (status) {
    query += ' AND t.status = ?';
    params.push(status);
  }
  if (start_date) {
    query += ' AND t.created_at >= ?';
    params.push(start_date);
  }
  if (end_date) {
    query += ' AND t.created_at <= ?';
    params.push(end_date);
  }

  query += ' ORDER BY t.created_at DESC';

  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Edit user details directly
router.put('/users/:id/edit', verifyToken, verifyAdmin, (req, res) => {
  const userId = req.params.id;
  const { full_name, phone_number, email, date_of_birth } = req.body;

  db.run(
    'UPDATE users SET full_name = ?, phone_number = ?, email = ?, date_of_birth = ? WHERE id = ?',
    [full_name, phone_number, email, date_of_birth, userId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to update user' });
      }

      // Log admin activity
      db.run(
        'INSERT INTO admin_activities (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)',
        [req.user.id, 'edit_user', 'user', userId, `Edited user details: ${full_name}`],
        function(err) {
          if (err) {
            console.error('Failed to log admin activity:', err);
          }
        }
      );

      res.json({ message: 'User updated successfully' });
    }
  );
});

// Get user full details
router.get('/users/:id/full', verifyToken, verifyAdmin, (req, res) => {
  const userId = req.params.id;

  db.get(
    `SELECT id, full_name, phone_number, email, date_of_birth, status, is_frozen, balance, created_at 
     FROM users WHERE id = ?`,
    [userId],
    (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json(user);
    }
  );
});

module.exports = router;