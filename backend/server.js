const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '.env') });

const express = require('express');
const app = express();
const port = process.env.PORT || 3001;

const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const sanitizeHtml = require('sanitize-html');

const saltRounds = 10;


// -------------------------
// CORS
// -------------------------

const corsOptions = {
    origin: 'http://localhost:5173',
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));


// -------------------------
// Middleware
// -------------------------

app.use(bodyParser.json());

app.use(express.urlencoded({
    extended: false
}));

app.use(session({
    secret: process.env.SESSION_SECRET || 'something',
    resave: false,
    saveUninitialized: false
}));

app.use(express.static(path.join(__dirname, '/dist')));


// -------------------------
// MySQL Connection
// -------------------------

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306
});


// Test MySQL connection

async function connectDB() {
    try {

        const connection = await db.getConnection();

        console.log('Connected to MySQL');

        connection.release();

    } catch (error) {

        console.error('Failed to connect to MySQL:', error.message);

    }
}

connectDB();


// -------------------------
// HOME
// -------------------------

app.get('/', (req, res) => {

    res.send('Hello World!');

});


// -------------------------
// PROFILE
// -------------------------

app.get('/profile', (req, res) => {

    if (!req.session.email) {

        return res.status(200).send({
            message: 'Not logged in'
        });

    }

    return res.send({

        email: req.session.email,
        name: req.session.name

    });

});


// -------------------------
// SANITIZE INPUT
// -------------------------

function sanitizeInput(input) {

    return sanitizeHtml(input, {

        allowedTags: [],
        allowedAttributes: {}

    });

}


// -------------------------
// LOGIN
// -------------------------

app.post('/login', async (req, res) => {

    let email = req.body.email;
    let password = req.body.password;

    email = sanitizeInput(email);
    password = sanitizeInput(password);

    try {

        const [rows] = await db.execute(

            'SELECT * FROM users WHERE email = ?',

            [email]

        );


        if (rows.length === 0) {

            return res.status(400).send({

                success: false,
                message: 'User not found'

            });

        }


        const user = rows[0];


        const match = await bcrypt.compare(

            password,
            user.password

        );


        if (!match) {

            return res.status(400).send({

                success: false,
                message: 'Incorrect email and password'

            });

        }


        req.session.name = user.name;

        req.session.email = user.email;


        return res.send({

            success: true,

            user: {

                id: user.id,
                name: user.name,
                email: user.email

            }

        });

    } catch (error) {

        console.error(error);

        return res.status(500).send({

            success: false,
            message: 'Error during the login process'

        });

    }

});


// -------------------------
// REGISTER
// -------------------------

app.post('/register', async (req, res) => {

    let name = req.body.name;
    let email = req.body.email;
    let password = req.body.password;
    let confirmPassword = req.body.confirmPassword;


    name = sanitizeInput(name);
    email = sanitizeInput(email);
    password = sanitizeInput(password);
    confirmPassword = sanitizeInput(confirmPassword);


    if (password !== confirmPassword) {

        return res.status(400).send({

            success: false,
            message: 'Passwords do not match.'

        });

    }


    try {

        // Check whether email already exists

        const [existingUsers] = await db.execute(

            'SELECT * FROM users WHERE email = ?',

            [email]

        );


        if (existingUsers.length > 0) {

            return res.status(400).send({

                success: false,
                message: 'Email already exists.'

            });

        }


        // Hash password

        const hashedPassword = await bcrypt.hash(

            password,
            saltRounds

        );


        // Insert user into MySQL

        const [result] = await db.execute(

            'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',

            [
                name,
                email,
                hashedPassword
            ]

        );


        console.log('User added!');


        // Create login session

        req.session.name = name;

        req.session.email = email;


        return res.status(201).send({

            success: true,

            message: 'Registration successful!',

            user: {

                id: result.insertId,
                name: name,
                email: email

            }

        });

    } catch (error) {

        console.error(error);

        return res.status(500).send({

            success: false,
            message: 'Error during registration.'

        });

    }

});


// -------------------------
// LOGOUT
// -------------------------

app.post('/logout', (req, res) => {

    if (!req.session.email) {

        return res.send('Already logged out');

    }


    req.session.destroy(function (error) {

        if (error) {

            return res.status(500).send({

                success: false,
                message: 'Could not log out'

            });

        }


        console.log('User logged out');

        return res.send('Logged out!');

    });

});


// -------------------------
// START SERVER
// -------------------------

app.listen(port, () => {

    console.log(`Example app listening on port ${port}`);

});