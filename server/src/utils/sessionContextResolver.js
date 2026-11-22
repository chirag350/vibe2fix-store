const service = require('../services/cart.service');

// The cart is always the authenticated user's own. (A previous version let a request header
// select another user's cart; that was an IDOR and has been removed.)
async function resolveContextCart(req) {
  return service.getCart(req.user.id);
}

module.exports = { resolveContextCart };
