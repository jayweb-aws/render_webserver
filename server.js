require("dotenv").config(); // load environment variables from .env file

const express = require("express");    // import express framework
const cors = require("cors");          // import cors middleware
const bcrypt = require("bcrypt");      // import bcrypt for password hashing
const jwt = require("jsonwebtoken");   // import json web token for authentication
const mongoose = require("mongoose");  // import mongoose for mongodb connection

const app = express();
const PORT = process.env.PORT || 3000;

// connect to mongodb using the connection string from .env (e.g., MONGO_URI)
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("connected to mongodb"))
  .catch((err) => console.error("error connecting to mongodb:", err));

// define the user schema and model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true }, // unique username
  email: { type: String, required: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

app.use(cors());          // enable cors for all routes
app.use(express.json());  // parse json request bodies

// password validation utility function
// rule: password must be at least 6 characters long and contain at least one letter and one number
function validatePassword(password) {
  const regex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/;
  return regex.test(password);
}

// register endpoint - saves user data to mongodb
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // check for duplicate username in the database
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ message: "username already taken" });
    }

    // validate the password
    if (!validatePassword(password)) {
      return res.status(400).json({
        message:
          "password must be at least 6 characters long and contain at least one letter and one number",
      });
    }

    // hash the password using bcrypt with 10 salt rounds
    const hashedPassword = await bcrypt.hash(password, 10);

    // create a new user document and save it to mongodb
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    // respond with a 201 status indicating successful registration
    res.status(201).json({ message: "user registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "registration failed", error });
  }
});

// login endpoint - authenticates user and generates a jwt token
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // find the user in mongodb by username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: "invalid username or password" });
    }

    // compare the provided password with the hashed password from the database
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "invalid username or password" });
    }

    // generate a jwt token using the secret from the environment variables
    const accessToken = jwt.sign(
      { username: user.username, email: user.email },
      process.env.JWT_SECRET, // ensure this variable is set in your .env file
      { expiresIn: "24h" }
    );

    // respond with the access token
    res.status(200).json({ accessToken });
  } catch (error) {
    res.status(500).json({ message: "login failed", error });
  }
});

// start the server on the specified port
app.listen(PORT, () => {
  console.log(`server running on port ${PORT}`);
});
