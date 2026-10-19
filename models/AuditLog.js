const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema({
  action: { type: String, required: true },
  performedBy: { type: String, required: true },
  details: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('AuditLog', AuditLogSchema);