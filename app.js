const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const app = express();

// Middleware to parse JSON data from incoming requests
app.use(express.json());
app.use(express.static('public'));

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

// Connect to MongoDB (Make sure you have MongoDB running)
mongoose.connect('mongodb://localhost:27017/signup-login', {
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
  firstname:String,
  lastname: String,
  email: String,
  password: String
});
const User = mongoose.model('User', userSchema);

// Regular expressions for email and password patterns
const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;

// Signup GET route
app.get('/signup', (req, res) => {
  res.render('signup', { validationErrors: [], signupError: '' });
});

// Signup POST route with validation
app.post('/signup', [
  body('firstname').notEmpty().withMessage('First name is required'),
  body('lastname').notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Invalid email format'),
  body('password').matches(passwordRegex).withMessage('Password requirements not met')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const validationErrors = errors.array().map(error => error.msg);
    return res.render('signup', { validationErrors, signupError: '' });
  }

  try {
    const email = req.body.email;

    // Check if the email already exists in the database
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      return res.render('signup', { signupError: 'User with this email already exists', validationErrors: [] });
    }
    
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const newUser = new User({
      firstname: req.body.firstname,
      lastname: req.body.lastname,
      email: req.body.email,
      password: hashedPassword
    });

    await newUser.save();
    console.log('User saved:', newUser);

    // Log in the user after successful signup
    req.session.userId = newUser._id; // Store user ID in session
    return res.redirect('/dashboard'); // Redirect to dashboard after successful signup and login
  } catch (error) {
    console.error('Route error:', error);
    res.status(500).send(`An error occurred: ${error.message}`);
  }
});

// Login GET route
app.get('/login', (req, res) => {
  res.render('login', { logout: req.query.logout === 'true', validationErrors: [], loginError: '' });
});

// Login POST route with validation
app.post('/login', [
  body('email').isEmail().withMessage('Invalid email format'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const validationErrors = errors.array().map(error => error.msg);
    return res.render('login', { validationErrors, loginError: '' });
  }

  try {
    const email = req.body.email;
    const user = await User.findOne({ email: email });
    if (!user) {
      return res.render('login', { loginError: 'User does not exist', validationErrors: [] });
    }

    const match = await bcrypt.compare(req.body.password, user.password);
    if (!match) {
      return res.render('login', { loginError: 'Incorrect password', validationErrors: [] }); // Set the loginError here
    }

    // Set session data and redirect to dashboard
    req.session.userId = user._id;
    return res.redirect('/dashboard');
  } catch (error) {
    console.error('Route error:', error);
    res.status(500).send(`An error occurred: ${error.message}`);
  }
});

// Dashboard route
app.get('/dashboard', async(req, res) => {
  try {
  // Check if user is logged in (session.userId exists)
  if (req.session.userId) {
    //Fetch the user's data from the database
    const user = await User.findById(req.session.userId);
    res.render('dashboard', { user });// Pass user data to the template
  } else {
    res.redirect('/signup'); // Redirect to signup if not logged in
  }
} catch (error) {
  console.error('Route error:', error);
  res.status(500).send(`An error occurred: ${error.message}`);
}
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
    }
    res.redirect('/login?logout=true'); // Redirect to login page after logout
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
