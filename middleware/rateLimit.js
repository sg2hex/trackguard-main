const rateLimit = require('express-rate-limit');
const loginRateLimitKey = (req) => rateLimit.ipKeyGenerator(req.ip);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Allow five login requests per IP during each window
  keyGenerator: loginRateLimitKey,
  message: 'Too many login attempts. Please try again after 15 minutes.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    res.status(options.statusCode).render('login', {
      error: null,
      rateLimitMessage: options.message
    });
  },
  skipSuccessfulRequests: false
});

const resetLoginLimiter = (req) => loginLimiter.resetKey(loginRateLimitKey(req));

const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: 'Too many password reset attempts. Please try again in an hour.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    if (req.path === '/forgot-password') {
      return res.status(options.statusCode).render('forgot-password', {
        error: options.message,
        message: null
      });
    }

    return res.status(options.statusCode).render('reset-password', {
      token: req.params.token || '',
      error: options.message,
      success: null
    });
  }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'Too many requests generated from this IP, please try again later.'
});

module.exports = { loginLimiter, resetLoginLimiter, passwordResetLimiter, apiLimiter };