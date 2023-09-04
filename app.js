const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const app = express();
const bodyParser = require('body-parser');

// Middleware to parse JSON data from incoming requests
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Middleware
app.set('view engine', 'ejs');
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

// Connect to MongoDB (Make sure you have MongoDB running)
mongoose.connect('mongodb://localhost:27017/register', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch(error => {
    console.error('MongoDB connection error:', error);
  });

// Define a mongoose schema for user
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  role: String,
  abilities: [{ action: String, subject: String }]
});
const User = mongoose.model('User', userSchema);

// Regular expressions for email and password patterns
const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;

// Signup POST route with validation
app.post('/signup', [
  body('username').notEmpty().withMessage('Username is required'),
  body('email').isEmail().withMessage('Invalid email format'),
  body('password').matches(passwordRegex).withMessage('Password requirements not met')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const validationErrors = errors.array().map(error => error.msg);
    return res.status(400).json({ errors: validationErrors });
  }

  try {
    // Check if the email already exists in the database
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
      role: 'admin',
      abilities: [
        {
          action: 'manage',
          subject: 'all',
        },
      ],
    });

    await newUser.save();
    console.log('User saved:', newUser);

    // Generate an access token
    const accessToken = jwt.sign({ userId: newUser._id }, 'your-secret-key');

    // Respond with user data and token
    const response = {
      userData: newUser,
      accessToken: accessToken,
      userAbilities: newUser.abilities,
    }
     console.log(response)
    return res.status(200).json(response);
  } catch (error) {
    console.error('Route error:', error);
    res.status(500).json({ error: 'An error occurred: ' + error.message });
  }
});

// Signup GET route
app.get('/signup', (req, res) => {
  res.render('signup', { validationErrors: [], signupError: '' });
});

// Login POST route
// Signup POST route with validation
app.post('/signup', [
  body('username').notEmpty().withMessage('Username is required'),
  body('email').isEmail().withMessage('Invalid email format'),
  body('password').matches(passwordRegex).withMessage('Password requirements not met')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const validationErrors = errors.array().map(error => error.msg);
    return res.status(400).json({ errors: validationErrors });
  }

  try {
    // Check if the email already exists in the database
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
      role: 'admin',
      abilities: [
        {
          action: 'manage',
          subject: 'all',
        },
      ],
    });

    await newUser.save();
    console.log('User saved:', newUser);

    // Generate an access token
    const accessToken = jwt.sign({ userId: newUser._id }, 'your-secret-key');

    // Respond with user data and token
    const response = {
      userData: newUser,
      accessToken: accessToken,
      userAbilities: newUser.abilities,
    }

    return res.status(200).json(response);
  } catch (error) {
    console.error('Route error:', error);
    res.status(500).json({ error: 'An error occurred: ' + error.message });
  }
});


// Dashboard route (protected)
app.get('/dashboard', authenticateToken, (req, res) => {
  try {
    // Access the user data from the request (provided by the middleware)
    const { userId, role, abilities } = req.session;

    // Check the user's role and abilities to determine access
    if (role === 'admin' || abilities.some(ability => ability.action === 'manage' && ability.subject === 'all')) {
      // User has access to the dashboard
      res.status(200).json({ message: 'You are authorized to access the dashboard.', userId });
    } else {
      // User does not have access
      res.status(403).json({ message: 'Access denied.' });
    }
  } catch (error) {
    console.error('Dashboard route error:', error);
    res.status(500).json({ error: 'An error occurred while accessing the dashboard.' });
  }
});

// Authentication middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  jwt.verify(token, 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    req.user = user;
    next();
  });
}

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
