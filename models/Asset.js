const mongoose = require('mongoose');

const AssetSchema = new mongoose.Schema({
  tagNumber: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  category: { type: String, required: true },
  status: { type: String, enum: ['Active', 'In-Repair', 'Retired'], default: 'Active' },
  assignedTo: { type: String, default: 'Unassigned' }
});

module.exports = mongoose.model('Asset', AssetSchema);