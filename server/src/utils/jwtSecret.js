const crypto = require('crypto');

let secret = process.env.JWT_SECRET;
if (!secret) {
  // No hard-coded fallback: a known default would let anyone forge tokens.
  secret = crypto.randomBytes(48).toString('hex');
  console.warn('[SECURITY] JWT_SECRET is not set; using a random per-process secret. Set JWT_SECRET so sessions survive restarts.');
}

module.exports = secret;
