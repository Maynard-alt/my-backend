const express = require('express');
const cors = require('cors');
const path = require('path');
const authRoutes = require('./auth');
const adminRoutes = require('./admin');
const transactionRoutes = require('./transactions');

const app = express();
const PORT = process.env.PORT || 3006;

// Middleware
app.use(cors());
app.use(express.json());

// API Routes - THESE SHOULD COME FIRST
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/transactions', transactionRoutes);

// TEST ENDPOINTS - Add these right after your API routes
app.get('/api/test', (req, res) => {
    res.json({ 
        message: 'Backend is working!',
        timestamp: new Date().toISOString(),
        status: 'OK',
        port: PORT
    });
});

app.post('/api/test-transaction', (req, res) => {
    // Mock transaction response for testing
    res.json({
        transactionId: Math.floor(Math.random() * 1000),
        uniqueId: 'TEST' + Date.now(),
        otp: '123456',
        message: 'Test transaction created successfully',
        status: 'success',
        testData: req.body
    });
});

// Debug endpoint to check headers and auth
app.get('/api/debug-headers', (req, res) => {
    res.json({
        headers: req.headers,
        authHeader: req.headers.authorization,
        timestamp: new Date().toISOString()
    });
});

// Static files - THESE SHOULD COME AFTER API ROUTES
app.use(express.static(path.join(__dirname, '../frontend')));

// Serve frontend pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/register.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/dashboard.html'));
});

app.get('/profile', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/profile.html'));
});

app.get('/transactions', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/transactions.html'));
});

app.get('/transfer', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/transfer.html'));
});

app.get('/loan', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/loan.html'));
});

app.get('/card', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/card.html'));
});

app.get('/support', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/support.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/admin.html'));
});

app.get('/receipt', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/receipt.html'));
});

// Catch-all for undefined API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ 
    error: 'API endpoint not found',
    path: req.originalUrl,
    method: req.method
  });
});

// Catch-all for frontend routes (SPA support)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

