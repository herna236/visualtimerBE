const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  numberOfTimersStarted: { type: Number, default: 0 },
  trialPeriodOver: { type: Boolean, default: false },
  hasPaid: { type: Boolean, default: false }
});

module.exports = mongoose.model('User', UserSchema);
