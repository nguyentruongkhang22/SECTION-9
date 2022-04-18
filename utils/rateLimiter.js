const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  max: 100,
  window: 60 * 60 * 1000,
  message: 'Too many request from this IP, try again later!',
});

module.exports = limiter;
