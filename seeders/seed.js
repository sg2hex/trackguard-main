const mongoose = require('mongoose');
require('dotenv').config();

const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/trackguard';

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'Admin' },
  createdAt: { type: Date, default: Date.now }
});

const assetSchema = new mongoose.Schema({
  name: String,
  description: String,
  employeeAccountable: String,
  status: { type: String, default: 'Active' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const auditSchema = new mongoose.Schema({
  action: String,
  performedBy: String,
  details: String,
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Asset = mongoose.models.Asset || mongoose.model('Asset', assetSchema);
const AuditLog = mongoose.models.AuditLog || mongoose.model('AuditLog', auditSchema);

const seedDatabase = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB Atlas for seeding...');

    await User.deleteMany({});
    await Asset.deleteMany({});
    await AuditLog.deleteMany({});

    // Create default Admin account
    await User.create({
      email: 'admin@trackguard.com',
      password: 'password123',
      role: 'Admin'
    });

    const seededAssets = await Asset.insertMany([
      {
        name: 'Dell XPS 15 Laptop',
        description: 'Primary workstation assigned to IT Lead for backend engineering',
        employeeAccountable: 'Mark (IT Lead)',
        status: 'Active'
      },
      {
        name: 'Smart TV 55"',
        description: 'TV 1 - Reserved for Lobby Digital Menu Board',
        employeeAccountable: 'Sebastian Marquez (Ops Manager)',
        status: 'Active'
      }
    ]);

    await AuditLog.insertMany([
      {
        action: 'SYSTEM_INITIALIZATION',
        performedBy: 'system@trackguard.com',
        details: 'Initial database seeding executed successfully.'
      },
      {
        action: 'ASSET_REGISTERED',
        performedBy: 'admin@trackguard.com',
        details: `Registered asset ${seededAssets[0].name} (#TG-${seededAssets[0]._id.toString().slice(-6)}) assigned to ${seededAssets[0].employeeAccountable}.`
      }
    ]);

    console.log('Database Seeding Successful! Created admin account, sample assets, and audit logs.');
    process.exit(0);
  } catch (error) {
    console.error('Seeding Failed:', error);
    process.exit(1);
  }
};

seedDatabase();