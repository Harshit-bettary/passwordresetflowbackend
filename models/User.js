const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetToken: { type: String,default: null,},
  resetTokenExpiry: { type: Date,default: null, },
});

module.exports = mongoose.model('User', userSchema);