
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join(__dirname, 'goldenbridge.db');
const db = new sqlite3.Database(dbPath);

async function seed() {
  try {
    // Create admin user with hashed password
    const hashedPassword = await bcrypt.hash('admin123', 10);
    
    db.run(
      'INSERT OR IGNORE INTO admins (username, password) VALUES (?, ?)',
      ['admin', hashedPassword],
      function(err) {
        if (err) {
          console.error('Error creating admin user:', err);
        } else {
          console.log('Admin user created successfully');
          console.log('Username: admin');
          console.log('Password: admin123');
        }
      }
    );

    // Create a sample approved user for testing
    const userPassword = await bcrypt.hash('user123', 10);
    db.run(
      `INSERT OR IGNORE INTO users 
      (full_name, phone_number, email, date_of_birth, password, status, balance) 
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ['John Doe', '+1234567890', 'user@example.com', '1990-01-01', userPassword, 'approved', 5000.00],
      function(err) {
        if (err) {
          console.error('Error creating sample user:', err);
        } else {
          console.log('Sample user created successfully');
          console.log('Email: user@example.com');
          console.log('Password: user123');
        }
      }
    );

    console.log('Database seeded successfully');
  } catch (error) {
    console.error('Error seeding database:', error);
  }
}

seed();

// Close database connection after seeding
setTimeout(() => {
  db.close();
}, 1000);