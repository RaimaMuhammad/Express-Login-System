
const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '.env') });

const express = require('express');
const app = express();
const port = process.env.PORT || 3001;

const cors = require('cors');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const sanitizeHtml = require('sanitize-html');

const saltRounds = 10;

// Trust Vercel's proxy so secure session cookies work.
app.set('trust proxy', 1);

// CORS
const corsOptions = {
    origin: true,
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET ||
        (process.env.NODE_ENV !== 'production' ? 'local-development-secret' : undefined),
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
}));

// Allow both /register and /api/register, etc.
app.use((req, res, next) => {
    if (req.url.startsWith('/api/')) {
        req.url = req.url.substring(4);
    }
    next();
});

// MySQL connection pool
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: Number(process.env.DB_PORT) || 3306,
    waitForConnections: true,
    connectionLimit: 5
});

// Test database connection
async function connectDB() {
    try {
        const connection = await db.getConnection();
        console.log('Connected to MySQL');
        connection.release();
    } catch (error) {
        console.error('MySQL connection failed:', error.message);
    }
}

connectDB();

// Sanitize input
function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    return sanitizeHtml(input, {
        allowedTags: [],
        allowedAttributes: {}
    }).trim();
}

// HOME
app.get('/', (req, res) => {
    res.send('Login backend is running');
});

// PROFILE
app.get('/profile', (req, res) => {
    if (!req.session.email) {
        return res.status(200).json({
            message: 'Not logged in'
        });
    }

    return res.json({
        email: req.session.email,
        name: req.session.name
    });
});

// LOGIN
app.post('/login', async (req, res) => {
    const email = sanitizeInput(req.body.email);
    const password = typeof req.body.password === 'string'
        ? req.body.password
        : '';

    try {
        const [rows] = await db.execute(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );

        if (rows.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'User not found'
            });
        }

        const user = rows[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.status(400).json({
                success: false,
                message: 'Incorrect email and password'
            });
        }

        req.session.name = user.name;
        req.session.email = user.email;

        return res.json({
            success: true,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Login error:', error.message);

        return res.status(500).json({
            success: false,
            message: 'Error during the login process'
        });
    }
});

// REGISTER
app.post('/register', async (req, res) => {
    const name = sanitizeInput(req.body.name);
    const email = sanitizeInput(req.body.email);
    const password = typeof req.body.password === 'string'
        ? req.body.password
        : '';
    const confirmPassword =
        typeof req.body.confirmPassword === 'string'
            ? req.body.confirmPassword
            : '';

    if (!name || !email || !password) {
        return res.status(400).json({
            success: false,
            message: 'Please fill in all required fields.'
        });
    }

    if (password !== confirmPassword) {
        return res.status(400).json({
            success: false,
            message: 'Passwords do not match.'
        });
    }

    try {
        const [existingUsers] = await db.execute(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Email already exists.'
            });
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const [result] = await db.execute(
            'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
            [name, email, hashedPassword]
        );

        req.session.name = name;
        req.session.email = email;

        return res.status(201).json({
            success: true,
            message: 'Registration successful!',
            user: {
                id: result.insertId,
                name,
                email
            }
        });
    } catch (error) {
        console.error('Registration error:', error.message);

        return res.status(500).json({
            success: false,
            message: 'Error during registration.'
        });
    }
});

// LOGOUT
app.post('/logout', (req, res) => {
    if (!req.session) {
        return res.json({ message: 'Already logged out' });
    }

    req.session.destroy((error) => {
        if (error) {
            return res.status(500).json({
                success: false,
                message: 'Could not log out'
            });
        }

        res.clearCookie('connect.sid');

        return res.json({
            success: true,
            message: 'Logged out!'
        });
    });
});

// Export Express app for Vercel.
// Run a local server only when not deployed on Vercel.
if (process.env.VERCEL !== '1') {
    app.listen(port, () => {
        console.log(`Server listening on port ${port}`);
    });
}

module.exports = app;

