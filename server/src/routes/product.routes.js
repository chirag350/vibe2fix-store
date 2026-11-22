const express = require('express');
const asyncHandler = require('../utils/asyncHandler');
const productController = require('../controllers/product.controller');

const router = express.Router();

// Product ids are UUIDs. Anything else (e.g. '../../admin/users') is rejected up front.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
router.param('id', (req, res, next, id) => {
  if (!UUID_RE.test(id)) {
    return res.status(400).json({ message: 'Invalid product id' });
  }
  next();
});

router.get('/', asyncHandler(productController.list));
router.get('/:id/reviews', asyncHandler(productController.listReviews));
router.get('/:id', asyncHandler(productController.getById));

module.exports = router;
