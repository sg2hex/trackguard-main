require('node:dns').setServers(['8.8.8.8']);

const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const path = require('path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const multer = require('multer');
require('dotenv').config();

// Safely import Middlewares
const authModule = require('./middleware/auth');
const isAuthenticated = typeof authModule === 'function' ? authModule : (authModule.isAuthenticated || ((req, res, next) => next()));

const rateLimitModule = require('./middleware/rateLimit');
const loginLimiter = rateLimitModule.loginLimiter || ((req, res, next) => next());
const passwordResetLimiter = rateLimitModule.passwordResetLimiter || ((req, res, next) => next());
const apiLimiter = rateLimitModule.apiLimiter || ((req, res, next) => next());
const { isValidEmail, getPasswordError, getUsernameError } = require('./middleware/validation');

const errorHandler = require('./middleware/errorHandler');

const app = express();

// Base Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
const profileImageDirectory = path.join(__dirname, 'public', 'uploads', 'profiles');
app.use('/profile-images', express.static(profileImageDirectory, {
  setHeaders: (res) => res.setHeader('X-Content-Type-Options', 'nosniff')
}));
app.use(apiLimiter);

// Session Setup
app.use(session({
  secret: process.env.SESSION_SECRET || 'trackguard_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 3600000 }
}));

app.get('/session-status', (req, res) => {
  res.set('Cache-Control', 'no-store');

  if (req.session && req.session.user) {
    return res.sendStatus(204);
  }

  return res.status(401).json({ error: 'Session expired' });
});

const isPasswordHash = (password) => /^\$2[aby]\$/.test(password);

const isMailConfigured = () => Boolean(
  process.env.SMTP_HOST
  && process.env.SMTP_USER
  && process.env.SMTP_PASS
  && process.env.SMTP_FROM
  && process.env.APP_BASE_URL
);

const sendPasswordResetEmail = async (email, resetUrl) => {
  if (!isMailConfigured()) {
    throw new Error('Password reset email is not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_FROM, and APP_BASE_URL.');
  }

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });

  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: email,
    subject: 'TrackGuard password reset',
    text: `Use this link to reset your TrackGuard password. It expires in 30 minutes:\n\n${resetUrl}\n\nIf you did not request this reset, you can ignore this email.`,
    html: `<p>Use the link below to reset your TrackGuard password. It expires in 30 minutes.</p><p><a href="${resetUrl}">Reset your password</a></p><p>If you did not request this reset, you can ignore this email.</p>`
  });
};

// --- Mongoose Schemas ---
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  emailNormalized: { type: String, unique: true, sparse: true },
  username: { type: String, trim: true },
  usernameNormalized: { type: String, unique: true, sparse: true },
  password: { type: String, required: true },
  role: { type: String, default: 'Admin' },
  profileName: { type: String, trim: true, maxlength: 40 },
  profilePicture: { type: String },
  passwordResetTokenHash: { type: String },
  passwordResetExpiresAt: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const inventorySystemSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  inviteCode: { type: String, required: true, unique: true },
  members: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: ['pending', 'active'], default: 'pending' },
    leaveRequested: { type: Boolean, default: false },
    joinedAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const assetSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: 'No description provided' },
  system: { type: mongoose.Schema.Types.ObjectId, ref: 'InventorySystem' },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  status: { type: String, default: 'Active' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { strict: false });

const auditSchema = new mongoose.Schema({
  system: { type: mongoose.Schema.Types.ObjectId, ref: 'InventorySystem' },
  action: { type: String, required: true },
  performedBy: { type: String, required: true },
  details: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);
const InventorySystem = mongoose.models.InventorySystem || mongoose.model('InventorySystem', inventorySystemSchema);
const Asset = mongoose.models.Asset || mongoose.model('Asset', assetSchema);
const AuditLog = mongoose.models.AuditLog || mongoose.model('AuditLog', auditSchema);

const profileImageExtensions = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp'
};

const profileImageUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, callback) => {
      fs.mkdir(profileImageDirectory, { recursive: true }, (err) => {
        callback(err, profileImageDirectory);
      });
    },
    filename: (req, file, callback) => {
      callback(null, `${crypto.randomBytes(16).toString('hex')}${profileImageExtensions[file.mimetype]}`);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, callback) => {
    if (!Object.prototype.hasOwnProperty.call(profileImageExtensions, file.mimetype)) {
      return callback(new Error('Choose a JPG, PNG, or WebP image.'));
    }
    return callback(null, true);
  }
});

// --- Routes ---

app.get('/', (req, res) => {
  res.redirect('/dashboard');
});

// GET Login Page
app.get('/login', (req, res) => {
  res.render('login', {
    error: null,
    success: req.query.reset === 'success' ? 'Your password has been reset. You can now sign in.' : null
  });
});

// GET Register Page
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// POST Register Handle
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
    const usernameNormalized = username.toLowerCase();
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';

    const usernameError = getUsernameError(username);
    if (usernameError) {
      return res.status(400).render('register', { error: usernameError });
    }

    if (!isValidEmail(cleanEmail)) {
      return res.status(400).render('register', { error: 'Invalid Email Address.' });
    }

    const passwordError = getPasswordError(password);
    if (passwordError) {
      return res.status(400).render('register', { error: passwordError });
    }

    const existingUser = await User.findOne({
      $or: [
        { emailNormalized: cleanEmail },
        { email: { $regex: `^${cleanEmail.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, $options: 'i' } }
      ]
    });
    if (existingUser) {
      return res.status(400).render('register', { error: 'Account with this email already exists.' });
    }

    const existingUsername = await User.findOne({
      $or: [
        { usernameNormalized },
        { username: { $regex: `^${username.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, $options: 'i' } }
      ]
    });
    if (existingUsername) {
      return res.status(400).render('register', { error: 'This username is already taken.' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = new User({
      email: cleanEmail,
      emailNormalized: cleanEmail,
      username,
      usernameNormalized,
      profileName: username,
      password: hashedPassword,
      role: 'Admin'
    });
    await newUser.save();

    try {
      await AuditLog.create({
        action: 'USER_REGISTERED',
        performedBy: cleanEmail,
        details: `New admin account registered: ${cleanEmail} (username: ${username})`
      });
    } catch (auditError) {
      console.error('Unable to write account registration audit log:', auditError);
    }

    return res.redirect('/login');
  } catch (err) {
    if (err && err.code === 11000) {
      const duplicateUsername = err.keyPattern && err.keyPattern.usernameNormalized;
      return res.status(400).render('register', {
        error: duplicateUsername ? 'This username is already taken.' : 'Account with this email already exists.'
      });
    }
    console.error('Registration Error:', err);
    res.status(500).render('register', { error: 'Failed to create account.' });
  }
});

// POST Login Handle
app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';

    if (!isValidEmail(cleanEmail)) {
      return res.status(400).render('login', { error: 'Invalid Email Address.' });
    }
    if (typeof password !== 'string' || password.length === 0) {
      return res.status(400).render('login', { error: 'Please enter your password.' });
    }

    const user = await User.findOne({ email: cleanEmail });

    const passwordMatches = user && (isPasswordHash(user.password)
      ? await bcrypt.compare(password, user.password)
      : user.password === password);

    if (!passwordMatches) {
      return res.status(401).render('login', { error: 'Invalid email or password.' });
    }

    if (!isPasswordHash(user.password)) {
      user.password = await bcrypt.hash(password, 12);
      await user.save();
    }

    req.session.user = { email: user.email, role: user.role || 'Admin' };

    req.session.save((err) => {
      if (err) {
        return res.status(500).render('login', { error: 'Session storage error.' });
      }
      res.redirect('/dashboard');
    });

  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).render('login', { error: 'Error processing login request.' });
  }
});

const logout = (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout Error:', err);
      return res.status(500).send('Unable to log out right now.');
    }

    res.clearCookie('connect.sid', { path: '/' });
    return res.redirect('/login');
  });
};

app.get('/logout', logout);
app.post('/logout', logout);

app.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { error: null, message: null });
});

app.post('/forgot-password', passwordResetLimiter, async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  if (!isValidEmail(email)) {
    return res.status(400).render('forgot-password', {
      error: 'Invalid Email Address.',
      message: null
    });
  }

  if (!isMailConfigured()) {
    console.error('Password reset unavailable: SMTP and APP_BASE_URL configuration is incomplete.');
    return res.status(503).render('forgot-password', {
      error: 'Password reset email is not configured. Please contact the administrator.',
      message: null
    });
  }

  try {
    const user = await User.findOne({ email });
    if (user) {
      const resetToken = crypto.randomBytes(32).toString('hex');
      user.passwordResetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
      user.passwordResetExpiresAt = new Date(Date.now() + 30 * 60 * 1000);
      await user.save();

      const resetUrl = new URL(`/reset-password/${resetToken}`, process.env.APP_BASE_URL).toString();
      try {
        await sendPasswordResetEmail(email, resetUrl);
      } catch (err) {
        user.passwordResetTokenHash = undefined;
        user.passwordResetExpiresAt = undefined;
        await user.save();
        throw err;
      }
    }

    return res.render('forgot-password', {
      error: null,
      message: 'If an account exists for that address, a password reset link has been sent. Check your inbox.'
    });
  } catch (err) {
    console.error('Password Reset Email Error:', err);
    return res.status(503).render('forgot-password', {
      error: 'We could not send a password reset email right now. Please try again later or contact the administrator.',
      message: null
    });
  }
});

app.get('/reset-password/:token', async (req, res) => {
  try {
    const tokenHash = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({
      passwordResetTokenHash: tokenHash,
      passwordResetExpiresAt: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).render('reset-password', {
        token: '',
        error: 'This password reset link is invalid or has expired. Request a new one.',
        success: null
      });
    }

    return res.render('reset-password', { token: req.params.token, error: null, success: null });
  } catch (err) {
    console.error('Password Reset Link Error:', err);
    return res.status(500).send('Unable to verify the password reset link.');
  }
});

app.post('/reset-password/:token', passwordResetLimiter, async (req, res) => {
  const passwordError = getPasswordError(req.body.password);
  if (passwordError) {
    return res.status(400).render('reset-password', {
      token: req.params.token,
      error: passwordError,
      success: null
    });
  }

  try {
    const tokenHash = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({
      passwordResetTokenHash: tokenHash,
      passwordResetExpiresAt: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).render('reset-password', {
        token: '',
        error: 'This password reset link is invalid or has expired. Request a new one.',
        success: null
      });
    }

    user.password = await bcrypt.hash(req.body.password, 12);
    user.passwordResetTokenHash = undefined;
    user.passwordResetExpiresAt = undefined;
    await user.save();

    return res.redirect('/login?reset=success');
  } catch (err) {
    console.error('Password Reset Error:', err);
    return res.status(500).render('reset-password', {
      token: req.params.token,
      error: 'Unable to reset your password right now. Please try again.',
      success: null
    });
  }
});

app.post('/systems', isAuthenticated, async (req, res) => {
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  if (name.length < 2 || name.length > 80) {
    return res.status(400).send('System name must be between 2 and 80 characters.');
  }

  try {
    const owner = await User.findOne({ email: req.session.user.email }).select('_id');
    if (!owner) return res.redirect('/logout');

    const system = await InventorySystem.create({
      name,
      owner: owner._id,
      inviteCode: crypto.randomBytes(5).toString('hex').toUpperCase()
    });
    await AuditLog.create({
      system: system._id,
      action: 'SYSTEM_CREATED',
      performedBy: req.session.user.email,
      details: `Created inventory system "${name}".`
    });
    return res.redirect(`/dashboard?system=${system._id}`);
  } catch (err) {
    console.error('Inventory System Creation Error:', err);
    return res.status(500).send('Unable to create inventory system.');
  }
});

app.post('/systems/join', isAuthenticated, async (req, res) => {
  const inviteCode = typeof req.body.inviteCode === 'string'
    ? req.body.inviteCode.trim().toUpperCase()
    : '';

  try {
    const user = await User.findOne({ email: req.session.user.email }).select('_id');
    if (!user) return res.redirect('/logout');
    const system = await InventorySystem.findOne({ inviteCode });
    if (!system) return res.status(404).send('No inventory system was found for that join code.');
    if (system.owner.equals(user._id)) {
      return res.status(400).send('You are already the administrator of this system.');
    }
    if (system.members.some((member) => member.user.equals(user._id))) {
      return res.status(400).send('You have already joined or requested to join this system.');
    }

    system.members.push({ user: user._id, status: 'pending' });
    await system.save();
    await AuditLog.create({
      system: system._id,
      action: 'JOIN_REQUESTED',
      performedBy: req.session.user.email,
      details: `Requested to join "${system.name}" as staff.`
    });
    return res.redirect('/dashboard?notice=requested');
  } catch (err) {
    console.error('Inventory System Join Error:', err);
    return res.status(500).send('Unable to request access to this inventory system.');
  }
});

app.post('/systems/:systemId/leave-request', isAuthenticated, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.systemId)) {
    return res.status(404).send('Inventory system not found.');
  }

  try {
    const user = await User.findOne({ email: req.session.user.email }).select('_id');
    if (!user) return res.redirect('/logout');
    const system = await InventorySystem.findById(req.params.systemId);
    if (!system) return res.status(404).send('Inventory system not found.');
    if (system.owner.equals(user._id)) {
      return res.status(400).send('The system administrator cannot request to leave as staff.');
    }

    const membership = system.members.find((member) =>
      member.user.equals(user._id) && member.status === 'active');
    if (!membership) return res.status(404).send('Active staff membership not found.');

    if (!membership.leaveRequested) {
      membership.leaveRequested = true;
      await system.save();
      await AuditLog.create({
        system: system._id,
        action: 'STAFF_LEAVE_REQUESTED',
        performedBy: req.session.user.email,
        details: `Requested to leave "${system.name}".`
      });
    }

    return res.redirect(`/dashboard?system=${system._id}&notice=leave-requested`);
  } catch (err) {
    console.error('Staff Leave Request Error:', err);
    return res.status(500).send('Unable to request to leave this inventory system.');
  }
});

app.post('/systems/:systemId/members/:memberId/approve', isAuthenticated, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.systemId)
      || !mongoose.isValidObjectId(req.params.memberId)) {
      return res.status(404).send('Pending staff request not found.');
    }
    const owner = await User.findOne({ email: req.session.user.email }).select('_id');
    if (!owner) return res.redirect('/logout');
    const system = await InventorySystem.findOne({ _id: req.params.systemId, owner: owner._id });
    if (!system) return res.status(404).send('Inventory system not found or access denied.');

    const membership = system.members.find((member) => member.user.equals(req.params.memberId));
    if (!membership || membership.status !== 'pending') {
      return res.status(404).send('Pending staff request not found.');
    }

    membership.status = 'active';
    membership.joinedAt = new Date();
    await system.save();
    const member = await User.findById(membership.user).select('email');
    await AuditLog.create({
      system: system._id,
      action: 'STAFF_APPROVED',
      performedBy: req.session.user.email,
      details: `Approved ${member ? member.email : 'a staff member'} to join "${system.name}".`
    });
    return res.redirect(`/dashboard?system=${system._id}`);
  } catch (err) {
    console.error('Staff Approval Error:', err);
    return res.status(500).send('Unable to approve staff request.');
  }
});

app.post('/systems/:systemId/members/:memberId/reject', isAuthenticated, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.systemId)
      || !mongoose.isValidObjectId(req.params.memberId)) {
      return res.status(404).send('Pending staff request not found.');
    }
    const owner = await User.findOne({ email: req.session.user.email }).select('_id');
    if (!owner) return res.redirect('/logout');
    const system = await InventorySystem.findOne({ _id: req.params.systemId, owner: owner._id });
    if (!system) return res.status(404).send('Inventory system not found or access denied.');

    const pendingRequest = system.members.find((member) =>
      member.user.equals(req.params.memberId) && member.status === 'pending');
    if (!pendingRequest) return res.status(404).send('Pending staff request not found.');

    system.members.pull(pendingRequest._id);
    await system.save();
    await AuditLog.create({
      system: system._id,
      action: 'STAFF_REQUEST_REJECTED',
      performedBy: req.session.user.email,
      details: 'Rejected a staff request.'
    });
    return res.redirect(`/dashboard?system=${system._id}`);
  } catch (err) {
    console.error('Staff Rejection Error:', err);
    return res.status(500).send('Unable to reject staff request.');
  }
});

app.post('/systems/:systemId/members/:memberId/approve-leave', isAuthenticated, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.systemId)
    || !mongoose.isValidObjectId(req.params.memberId)) {
    return res.status(404).send('Pending staff leave request not found.');
  }

  const session = await mongoose.startSession();
  try {
    const owner = await User.findOne({ email: req.session.user.email }).select('_id');
    if (!owner) return res.redirect('/logout');

    let approvedSystemId = null;
    await session.withTransaction(async () => {
      const system = await InventorySystem.findOne({
        _id: req.params.systemId,
        owner: owner._id
      }).session(session);
      if (!system) return;

      const membership = system.members.find((member) =>
        member.user.equals(req.params.memberId)
        && member.status === 'active'
        && member.leaveRequested);
      if (!membership) return;

      const member = await User.findById(membership.user).select('email').session(session);
      await Asset.updateMany(
        { system: system._id, assignedTo: membership.user },
        { $set: { assignedTo: null, updatedAt: new Date() } },
        { session }
      );
      system.members.pull(membership._id);
      await system.save({ session });
      await new AuditLog({
        system: system._id,
        action: 'STAFF_LEAVE_APPROVED',
        performedBy: req.session.user.email,
        details: `Approved ${member ? member.email : 'a staff member'} to leave "${system.name}"; assigned assets were unassigned.`
      }).save({ session });
      approvedSystemId = system._id.toString();
    });

    if (!approvedSystemId) {
      return res.status(404).send('Pending staff leave request not found.');
    }
    return res.redirect(`/dashboard?system=${approvedSystemId}`);
  } catch (err) {
    console.error('Staff Leave Approval Error:', err);
    return res.status(500).send('Unable to approve the staff leave request.');
  } finally {
    await session.endSession();
  }
});

app.post('/systems/:systemId/members/:memberId/reject-leave', isAuthenticated, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.systemId)
      || !mongoose.isValidObjectId(req.params.memberId)) {
      return res.status(404).send('Pending staff leave request not found.');
    }
    const owner = await User.findOne({ email: req.session.user.email }).select('_id');
    if (!owner) return res.redirect('/logout');
    const system = await InventorySystem.findOne({ _id: req.params.systemId, owner: owner._id });
    if (!system) return res.status(404).send('Inventory system not found or access denied.');

    const membership = system.members.find((member) =>
      member.user.equals(req.params.memberId)
      && member.status === 'active'
      && member.leaveRequested);
    if (!membership) return res.status(404).send('Pending staff leave request not found.');

    membership.leaveRequested = false;
    await system.save();
    const member = await User.findById(membership.user).select('email');
    await AuditLog.create({
      system: system._id,
      action: 'STAFF_LEAVE_REJECTED',
      performedBy: req.session.user.email,
      details: `Rejected ${member ? member.email : 'a staff member'}'s request to leave "${system.name}".`
    });
    return res.redirect(`/dashboard?system=${system._id}`);
  } catch (err) {
    console.error('Staff Leave Rejection Error:', err);
    return res.status(500).send('Unable to reject the staff leave request.');
  }
});

app.post('/systems/:systemId/delete', isAuthenticated, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.systemId)) {
    return res.status(404).send('Inventory system not found.');
  }

  const session = await mongoose.startSession();
  try {
    const owner = await User.findOne({ email: req.session.user.email }).select('_id');
    if (!owner) return res.redirect('/logout');

    let deleted = false;
    await session.withTransaction(async () => {
      const system = await InventorySystem.findOne({
        _id: req.params.systemId,
        owner: owner._id
      }).session(session);
      if (!system) return;

      await Asset.deleteMany({ system: system._id }, { session });
      await AuditLog.deleteMany({ system: system._id }, { session });
      await InventorySystem.deleteOne({ _id: system._id, owner: owner._id }, { session });
      deleted = true;
    });

    if (!deleted) return res.status(404).send('Inventory system not found or access denied.');
    return res.redirect('/dashboard?notice=deleted');
  } catch (err) {
    console.error('Inventory System Deletion Error:', err);
    return res.status(500).send('Unable to delete inventory system.');
  } finally {
    await session.endSession();
  }
});

// Render system lists by default, and a selected system only after checking membership.
app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.session.user.email })
      .select('_id profileName profilePicture');
    if (!user) return res.redirect('/logout');

    const createdSystems = await InventorySystem.find({ owner: user._id }).sort({ createdAt: -1 });
    const memberships = await InventorySystem.find({
      members: { $elemMatch: { user: user._id, status: 'active' } }
    }).sort({ createdAt: -1 });
    const pendingMemberships = await InventorySystem.find({
      members: { $elemMatch: { user: user._id, status: 'pending' } }
    }).sort({ createdAt: -1 });

    const createdSystemCards = await Promise.all(createdSystems.map(async (system) => {
      const pendingJoinRequests = system.members
        .filter((member) => member.status === 'pending')
      const pendingLeaveRequests = system.members
        .filter((member) => member.status === 'active' && member.leaveRequested);
      const requestIds = [...new Set([
        ...pendingJoinRequests.map((member) => member.user.toString()),
        ...pendingLeaveRequests.map((member) => member.user.toString())
      ])];
      const requestUsers = requestIds.length
        ? await User.find({ _id: { $in: requestIds } }).select('profileName email')
        : [];
      const requestUsersById = new Map(requestUsers.map((requestUser) => [
        requestUser._id.toString(), requestUser
      ]));
      const formatRequest = (membership) => {
        const memberId = membership.user.toString();
        const requestUser = requestUsersById.get(memberId);
        return {
          id: memberId,
          name: requestUser ? requestUser.profileName || requestUser.email : 'Staff member',
          email: requestUser ? requestUser.email : 'Account unavailable'
        };
      };
      return {
        id: system._id.toString(),
        name: system.name,
        inviteCode: system.inviteCode,
        pendingMembers: pendingJoinRequests.map(formatRequest),
        leaveRequests: pendingLeaveRequests.map(formatRequest)
      };
    }));

    let selectedSystem = null;
    let isSystemAdmin = false;
    let leaveRequested = false;
    let assets = [];
    let auditLogs = [];
    let staff = [];

    if (typeof req.query.system === 'string') {
      if (!mongoose.isValidObjectId(req.query.system)) {
        return res.status(404).send('Inventory system not found.');
      }
      selectedSystem = await InventorySystem.findById(req.query.system);
      if (!selectedSystem) return res.status(404).send('Inventory system not found.');

      isSystemAdmin = selectedSystem.owner.equals(user._id);
      const activeMembership = selectedSystem.members.find((member) =>
        member.user.equals(user._id) && member.status === 'active');
      if (!isSystemAdmin && !activeMembership) {
        return res.status(403).send('You do not have access to this inventory system.');
      }
      leaveRequested = Boolean(activeMembership && activeMembership.leaveRequested);

      const assetFilter = { system: selectedSystem._id };
      if (!isSystemAdmin) assetFilter.assignedTo = user._id;
      assets = await Asset.find(assetFilter)
        .populate('assignedTo', 'profileName email')
        .sort({ updatedAt: -1 });

      if (isSystemAdmin) {
        auditLogs = await AuditLog.find({ system: selectedSystem._id }).sort({ timestamp: -1 });
        const activeStaffIds = selectedSystem.members
          .filter((member) => member.status === 'active')
          .map((member) => member.user);
        const staffUsers = activeStaffIds.length
          ? await User.find({ _id: { $in: activeStaffIds } }).select('profileName email')
          : [];
        staff = staffUsers.map((staffUser) => ({
          id: staffUser._id.toString(),
          name: staffUser.profileName || staffUser.email,
          email: staffUser.email
        }));
      }
    }

    const profileName = user.profileName || user.username || 'System Admin';
    const profileInitials = profileName.split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0].toUpperCase())
      .join('');

    return res.render('dashboard', {
      createdSystems: createdSystemCards,
      joinedSystems: memberships.map((system) => ({
        id: system._id.toString(),
        name: system.name,
        leaveRequested: Boolean(system.members.find((member) =>
          member.user.equals(user._id))?.leaveRequested)
      })),
      pendingSystems: pendingMemberships.map((system) => ({
        id: system._id.toString(),
        name: system.name
      })),
      selectedSystem: selectedSystem ? {
        id: selectedSystem._id.toString(),
        name: selectedSystem.name,
        inviteCode: selectedSystem.inviteCode
      } : null,
      isSystemAdmin,
      leaveRequested,
      assets,
      auditLogs,
      staff,
      profileName,
      profilePicture: user.profilePicture || null,
      profileInitials: profileInitials || 'SA',
      notice: req.query.notice === 'requested'
        ? 'Join request sent. A system administrator must approve you before you can access the inventory.'
        : req.query.notice === 'leave-requested'
          ? 'Leave request sent. You will remain a staff member until the administrator reviews it.'
          : null,
      showDeletedNotice: req.query.notice === 'deleted'
    });
  } catch (err) {
    console.error('Dashboard Load Error:', err);
    return res.status(500).send('Error loading dashboard');
  }
});

app.post('/profile', isAuthenticated, (req, res, next) => {
  profileImageUpload.single('profilePicture')(req, res, (err) => {
    if (!err) return next();

    if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).send('Profile pictures must be 2 MB or smaller.');
    }
    if (err.message === 'Choose a JPG, PNG, or WebP image.') {
      return res.status(400).send(err.message);
    }
    return next(err);
  });
}, async (req, res) => {
  const profileName = typeof req.body.profileName === 'string'
    ? req.body.profileName.trim()
    : '';

  if (profileName.length < 1 || profileName.length > 40) {
    if (req.file) await fs.promises.unlink(req.file.path);
    return res.status(400).send('Profile name must be between 1 and 40 characters.');
  }

  try {
    const user = await User.findOne({ email: req.session.user.email });
    if (!user) {
      if (req.file) await fs.promises.unlink(req.file.path);
      return res.redirect('/logout');
    }

    const oldProfilePicture = user.profilePicture;
    user.profileName = profileName;
    if (req.file) {
      user.profilePicture = `/profile-images/${req.file.filename}`;
    }
    await user.save();

    if (req.file && oldProfilePicture && oldProfilePicture.startsWith('/profile-images/')) {
      const oldImagePath = path.join(profileImageDirectory, path.basename(oldProfilePicture));
      try {
        await fs.promises.unlink(oldImagePath);
      } catch (err) {
        if (err.code !== 'ENOENT') {
          console.error('Unable to remove previous profile picture:', err);
        }
      }
    }

    return res.redirect('/dashboard');
  } catch (err) {
    if (req.file) {
      try {
        await fs.promises.unlink(req.file.path);
      } catch (cleanupError) {
        if (cleanupError.code !== 'ENOENT') {
          console.error('Unable to cleanup temporary upload file:', cleanupError);
        }
      }
    }
    console.error('Profile Update Error:', err);
    return res.status(500).send('Unable to update profile.');
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
const BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;
const DATABASE_NAME = process.env.MONGODB_DB_NAME || 'trackguard';

mongoose.connect(process.env.MONGO_URI, { dbName: DATABASE_NAME })
  .then(() => {
    console.log('Connected to MongoDB Atlas');
    app.listen(PORT, () => {
      console.log(`TrackGuard server running on ${BASE_URL}`);
    });
  })
  .catch((err) => console.error('Database Connection Error:', err));