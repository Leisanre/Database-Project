const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Serve static files (e.g., CSS, JS, images) from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// Set up MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'Owner',
    password: 'owner',
    database: 'BookSale'
});

// Connect to the database
db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err.stack);
        return;
    }
    console.log('MySQL connected...');
});

// Route to serve BookSaleTest.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'BookSaleTest.html'));
});

// Route to serve BookSaleRegisterPage.html (use the static folder path)
app.get('/BookSaleRegisterPage', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'BookSaleRegisterPage.html'));
});

// Sign-up API endpoint
app.post('/api/signup', async (req, res) => {
    const { email, first_name, middle_name, last_name, password } = req.body;

    // Validate required fields
    if (!email || !first_name || !middle_name || !last_name || !password) {
        return res.status(400).json({ success: false, message: 'All required fields must be filled.' });
    }

    // Password validation (e.g., minimum 8 characters)
    if (password.length < 8) {
        return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long.' });
    }

    try {
        // Check if the email already exists
        const [existingUser] = await db.promise().query('SELECT * FROM Users WHERE email = ?', [email]);

        if (existingUser.length > 0) {
            return res.status(409).json({ success: false, message: 'Email already exists.' });
        }

        // Hash the password using bcrypt
        const hash = await bcrypt.hash(password, 10);

        // Insert the new user into the database
        const newUser = {
            email,
            first_name,
            middle_name,
            last_name,
            password_hash: hash
        };

        await db.promise().query('INSERT INTO Users SET ?', newUser);

        // Respond with success
        res.json({ success: true, message: 'User created successfully!' });
    } catch (err) {
        console.error('Error inserting user:', err);
        res.status(500).json({ success: false, message: 'Error registering user, please try again.' });
    }
});

// Login API endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    // Check if both fields are provided
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    try {
        const [userResult] = await db.promise().query('SELECT * FROM Users WHERE email = ?', [email]);

        if (userResult.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }

        const user = userResult[0];

        // Compare the password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }

        // Login successful
        res.json({ success: true, message: 'Login successful!' });
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ success: false, message: 'Error during login, please try again.' });
    }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
