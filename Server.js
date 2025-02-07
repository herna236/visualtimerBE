const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const User = require('./models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

const corsOptions = {
  origin: ['https://visualtimerf.onrender.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Added OPTIONS method
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200,
};

// Handle OPTIONS requests (preflight)
app.options('*', cors(corsOptions));

// Use CORS middleware
app.use(cors(corsOptions));
app.use(express.json()); // Using built-in express.json()

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('Error connecting to MongoDB:', err));

// Middleware to authenticate the user
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('Access denied. No token provided.');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id);
    if (!req.user) return res.status(401).send('User not found');
    next();
  } catch (error) {
    res.status(403).send('Invalid token.');
  }
};

// User Registration
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).send({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      email,
      password: hashedPassword,
      numberOfTimersStarted: 0,
      trialPeriodOver: false,
      hasPaid: false
    });

    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, userId: user._id });

  } catch (error) {
    console.error('Error registering user:', error);
    res.status(400).send({ message: 'Error registering user: ' + error.message });
  }
});

// User Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send('User not found');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send('Invalid credentials');

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, userId: user._id });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(400).send('Error logging in: ' + error.message);
  }
});

// Get User Profile
app.get('/profile', authenticate, (req, res) => {
  res.json({
    email: req.user.email,
    numberOfTimersStarted: req.user.numberOfTimersStarted,
    trialPeriodOver: req.user.trialPeriodOver,
    hasPaid: req.user.hasPaid
  });
});

// Edit user profile
app.put('/edit-profile', authenticate, async (req, res) => {
  console.log('Edit profile route hit');
  const { newEmail } = req.body;

  try {
    if (!newEmail || !validateEmail(newEmail)) {
      return res.status(400).json({ message: 'Invalid email address' });
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id, // User ID from the token
      { email: newEmail },
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ message: 'Email updated successfully', user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

// Email validation function
const validateEmail = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase());
};

// Get User Email
app.get('/user-email', authenticate, (req, res) => {
  res.json({ email: req.user.email });
});

// Delete User Account
app.delete('/delete-account', authenticate, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.user._id);
    res.status(200).send('User account deleted successfully');
  } catch (error) {
    res.status(400).send('Error deleting user account: ' + error.message);
  }
});

// User Status
app.get('/user-status/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(400).send('User not found');

    res.json({
      trialPeriodOver: user.trialPeriodOver,
      numberOfTimersStarted: user.numberOfTimersStarted,
      hasPaid: user.hasPaid
    });
  } catch (error) {
    res.status(400).send('Error fetching user status: ' + error.message);
  }
});

// Start Timer
app.post('/start-timer', authenticate, async (req, res) => {
  const userId = req.user._id;

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(400).send('User not found');

    user.numberOfTimersStarted += 1;

    if (user.numberOfTimersStarted >= 5) {
      user.trialPeriodOver = true;
    }

    await user.save();
    res.status(200).send('Timer started');
  } catch (error) {
    res.status(400).send('Error starting timer: ' + error.message);
  }
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });
}

module.exports = app;
