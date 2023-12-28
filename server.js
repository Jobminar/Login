
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import cors from 'cors';
import Login from './Model.js';
import dotenv from 'dotenv';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI;
const EMAIL_USERNAME = process.env.EMAIL_USERNAME;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;

mongoose.connect(MONGODB_URI, {
  // useNewUrlParser: true,
  // useUnifiedTopology: true,
})
  .then(() => console.log(`MongoDB connected successfully to ${MONGODB_URI}`))
  .catch((error) => console.error("Error connecting to MongoDB:", error));

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    type: 'OAuth2',
    user: EMAIL_USERNAME,
    clientId: 'YOUR_CLIENT_ID',
    clientSecret: 'YOUR_CLIENT_SECRET',
    refreshToken: 'YOUR_REFRESH_TOKEN',
    accessToken: 'YOUR_ACCESS_TOKEN', 
  },
});

app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new Login({ email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await Login.findOne({ email });

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    res.status(200).json({ message: 'Login successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await Login.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiration = new Date(Date.now() + 3600000); 

    user.resetToken = resetToken;
    user.resetTokenExpiration = resetTokenExpiration;

    await user.save();

    const mailOptions = {
      from: EMAIL_USERNAME,
      to: user.email,
      subject: 'Password Reset',
      html: `
        <p>You requested a password reset</p>
        <p>Click this <a href="http://localhost:3000/reset-password/${resetToken}">link</a> to reset your password.</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: 'Password reset link sent to your email' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post("/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    const user = await Login.findOne({
      resetToken: token,
      resetTokenExpiration: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    user.password = hashedPassword;
    user.resetToken = null;
    user.resetTokenExpiration = null;

    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
