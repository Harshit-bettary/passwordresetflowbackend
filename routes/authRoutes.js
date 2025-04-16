const express = require('express');
const router = express.Router();
const { signup, login, requestPasswordReset, verifyResetToken, resetPassword } = require('../controllers/authcontroller');

router.post('/signup', signup);
router.post('/login', login);
router.post('/forgot-password', requestPasswordReset);
router.get('/reset-password/:token', verifyResetToken);
router.post('/reset-password', resetPassword);

module.exports = router;