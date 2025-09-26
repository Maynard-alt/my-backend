// New API endpoints for proper ticket management
const express = require('express');
const db = require('./database');
const router = express.Router();

// Get all tickets with message counts
router.get('/', verifyToken, verifyAdmin, (req, res) => {
    db.all(`
        SELECT s.*, u.full_name as user_name, 
               (SELECT COUNT(*) FROM ticket_messages WHERE ticket_id = s.id) as message_count
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

// Get full conversation for a ticket
router.get('/:id/conversation', verifyToken, verifyAdmin, (req, res) => {
    const ticketId = req.params.id;
    
    db.all(`
        SELECT m.*, 
               u.full_name as user_name,
               a.username as admin_name,
               CASE 
                   WHEN m.admin_id IS NOT NULL THEN 'admin'
                   ELSE 'user'
               END as sender_type
        FROM ticket_messages m
        LEFT JOIN users u ON m.user_id = u.id
        LEFT JOIN admins a ON m.admin_id = a.id
        WHERE m.ticket_id = ?
        ORDER BY m.created_at ASC
    `, [ticketId], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(rows);
    });
});

// Admin responds to ticket
router.post('/:id/respond', verifyToken, verifyAdmin, (req, res) => {
    const ticketId = req.params.id;
    const { message, status } = req.body;
    const adminId = req.user.id;

    // Insert new message
    db.run(
        `INSERT INTO ticket_messages (ticket_id, admin_id, message, is_admin_response) 
         VALUES (?, ?, ?, 1)`,
        [ticketId, adminId, message],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to save response' });
            }

            // Update ticket status and timestamp
            db.run(
                `UPDATE support_tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
                [status || 'in progress', ticketId],
                function(err) {
                    if (err) {
                        console.error('Failed to update ticket status:', err);
                    }
                    
                    res.json({ 
                        message: 'Response sent successfully',
                        messageId: this.lastID 
                    });
                }
            );
        }
    );
});

// User adds message to ticket (from support.html)
router.post('/:id/message', verifyToken, (req, res) => {
    const ticketId = req.params.id;
    const { message } = req.body;
    const userId = req.user.id;

    // Verify user owns this ticket
    db.get('SELECT user_id FROM support_tickets WHERE id = ?', [ticketId], (err, ticket) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!ticket || ticket.user_id !== userId) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Insert user message
        db.run(
            `INSERT INTO ticket_messages (ticket_id, user_id, message, is_admin_response) 
             VALUES (?, ?, ?, 0)`,
            [ticketId, userId, message],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Failed to save message' });
                }

                // Update ticket timestamp
                db.run(
                    `UPDATE support_tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
                    [ticketId],
                    function(err) {
                        if (err) {
                            console.error('Failed to update ticket timestamp:', err);
                        }
                        
                        res.json({ 
                            message: 'Message added successfully',
                            messageId: this.lastID 
                        });
                    }
                );
            }
        );
    });
});