const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');

const app = express();

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/myapp', { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
});

// Define User schema
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true }
});

// Hash password before saving user to database
userSchema.pre('save', function(next) {
    const user = this;
    if (!user.isModified('password')) return next();
    bcrypt.hash(user.password, 10, (err, hash) => {
        if (err) return next(err);
        user.password = hash;
        next();
    });
});

// Define User model
const User = mongoose.model('User', userSchema);

// Define middleware to log incoming requests
app.use((req, res, next) => {
    console.log(`Incoming request: ${req.method} ${req.url}`);
    res.on('finish', () => {
        console.log(`Response sent: ${res.statusCode}`);
    });
    next();
});

// Define a route to redirect users to the login page
app.get('/', (req, res) => {
    res.redirect('/login');
});

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// Define a route to serve the login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Define a route to serve the create account page
app.get('/newaccount', (req, res) => {
    res.redirect(path.join(__dirname, 'public', 'newaccount.html'));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // Check username and password against a database or hardcoded values
    // For simplicity, we'll just check if they are non-empty strings
    if (username && password) {
        // Authentication successful
        res.send('Login successful!');
    } else {
        // Authentication failed
        res.send('Invalid username or password.');
    }
});

// Handle account creation form submission
app.post('/createaccount', async (req, res) => {
    const { username, password } = req.body;
    // Validate inputs
    if (!username || !password) {
        return res.status(400).send('Username and password are required.');
    }
    try {
        // Generate a salt
        const saltRounds = 10;
        const salt = await bcrypt.genSalt(saltRounds);
        // Hash password with the generated salt
        const hashedPassword = await bcrypt.hash(password, salt);
        // Create a new user instance with the hashed password
        const newUser = new User({ username, password: hashedPassword });
        // Save user to database
        await newUser.save();
        res.send('Account created successfully!');
    } catch (error) {
        if (error.code === 11000) {
            // Duplicate key error (username already exists)
            return res.status(400).send('Username already exists.');
        }
        console.error('Error creating user:', error);
        res.status(500).send('Internal server error.');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
