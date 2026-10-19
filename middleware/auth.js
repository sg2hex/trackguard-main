module.exports = {
  isAuthenticated: (req, res, next) => {
    if (req.session && req.session.user) {
      return next();
    }
    return res.redirect('/login');
  },

  isAdmin: (req, res, next) => {
    if (req.session && req.session.user && req.session.user.role === 'Admin') {
      return next();
    }
    return res.status(403).send('Access Denied: Insufficient Privileges');
  }
};