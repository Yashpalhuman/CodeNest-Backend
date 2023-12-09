require('dotenv').config();

const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors=require('cors');

const app = express();
const port = 5000;
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE
});


db.connect((err) => {
  if (err) {
    console.error('MySQL connection error:', err);
    throw err;
  }
  console.log('Connected to MySQL');
});

app.use(bodyParser.json());
app.use(cors());

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  console.log('signup failed due to username exists');
  // Retrieving user from the database based on username
  const getUserQuery = 'SELECT * FROM users WHERE username = ?';
  db.query(getUserQuery, [username], async (err, results) => {
    if (err) {
      console.error('Error checking username:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (results.length === 0) {
      console.log('username does not exists ');
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const user = results[0];

    // Checking if the provided password matches the hashed password in the database
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      console.log('password does not match');
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // username and password matches
    console.log('user successfully logged in');
    res.status(200).json({ message: 'Login successful', user });
  });
});

app.post('/signup', async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;

  // Checking if passwords match
  if (password !== confirmPassword) {
    console.log('signup failed due to password mismatch');
    return res.status(400).json({ message: 'Passwords do not match' });
  }

  // Checking if username already exists
  const usernameExistsQuery = 'SELECT * FROM users WHERE username = ?';
  db.query(usernameExistsQuery, [username], (err, results) => {
    if (err) {
      console.error('Error checking username:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (results.length > 0) {
      console.log('signup failed due to username exists');
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Checking if email already exists
    const emailExistsQuery = 'SELECT * FROM users WHERE email = ?';
    db.query(emailExistsQuery, [email], async (err, results) => {
      if (err) {
        console.error('Error checking email:', err);
        return res.status(500).json({ message: 'Internal server error' });
      }

      if (results.length > 0) {
        console.log('signup failed due to emai exists');
        return res.status(400).json({ message: 'Email already exists' });
      }

      // Hashing the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Inserting user into the database
      const insertUserQuery = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
      db.query(insertUserQuery, [username, email, hashedPassword], (err, results) => {
        if (err) {
          console.error('Error inserting user:', err);
          return res.status(500).json({ message: 'Internal server error' });
        }
        console.log('User registered successfully');
        res.status(201).json({ message: 'User registered successfully' });
      });
    });
  });
});



// Starting the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
