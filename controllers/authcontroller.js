const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const signup = async (req, res) => {
  try {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists',
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      email,
      password: hashedPassword,
    });
    await newUser.save();

    res.status(201).json({
      success: true,
      message: 'SignUp successful',
      user: { id: newUser._id, email: newUser.email },
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error',
      error: err.message,
    });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
      },
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Internal Server Error',
      error: err.message,
    });
  }
};
const requestPasswordReset = async (req, res) => {
    try {
      const { email } = req.body;
      console.log('Requesting reset for email:', email);
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.status(400).json({
          success: false,
          message: 'User not found',
        });
      }
  
      const resetToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      user.resetToken = resetToken
      user.resetTokenExpiry = new Date(Date.now() + 3600000);
      console.log('Saving reset token...');
      await user.save();
      console.log('Saved user:', user);
  
      const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
      await transporter.sendMail({
        to: email,
        subject: 'Password Reset',
        html: `<p>Click <a href="${resetLink}">here</a> to reset your password. This link expires in 1 hour.</p>`,
      });
      console.log('Reset email sent to:', email);
  
      res.json({
        success: true,
        message: 'Password reset link sent to email',
      });
    } catch (err) {
      console.error('Error in requestPasswordReset:', err);
      res.status(500).json({
        success: false,
        message: 'Internal Server Error',
        error: err.message,
      });
    }
  };


const verifyResetToken = async (req, res) => {
    try {
      const { token } = req.params;
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      const user = await User.findById(decoded.userId);
      console.log('User by ID:', user);
      if (user.resetToken !== token) {
        console.log('Token mismatch!');
      }
      if (user.resetTokenExpiry <= Date.now()) {
        console.log('Token expired!');
      }
      

      // const user = await User.findOne({
      //   _id: decoded.userId,
      //   resetToken: token,
      //   resetTokenExpiry: { $gt: Date.now() },
      // });
  
      if (!user) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired token',
        });
      }
  
      res.status(200).json({
        success: true,
        message: 'Token is valid',
      });
    } catch (err) {
      console.error('Error in verifyResetToken:', err.name, err.message);
      res.status(400).json({
        success: false,
        message: err.name === 'TokenExpiredError' ? 'Token has expired' : 'Invalid token',
      });
    }
  };

  const resetPassword = async (req, res) => {
    try {
      const { token, newPassword } = req.body;
      console.log('Reset password token:', token);
  
      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'No token provided',
        });
      }
  
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log('Decoded token:', decoded);
  
      const user = await User.findOne({
        _id: decoded.userId,
        resetToken: token,
        resetTokenExpiry: { $gt: Date.now() },
      });
      console.log('User found:', user ? user : 'No user');
  
      if (!user) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired token',
        });
      }
  
      user.password = await bcrypt.hash(newPassword, 10); 
      user.resetToken = undefined;
      user.resetTokenExpiry = undefined;
      await user.save();
  
      res.json({
        success: true,
        message: 'Password reset successful',
      });
    } catch (err) {
      console.error('Error in resetPassword:', err.name, err.message);
      res.status(400).json({
        success: false,
        message: err.name === 'TokenExpiredError' ? 'Token has expired' : 'Invalid token',
      });
    }
  };
module.exports = {
  signup,
  login,
  requestPasswordReset,
  verifyResetToken,
  resetPassword,
};
