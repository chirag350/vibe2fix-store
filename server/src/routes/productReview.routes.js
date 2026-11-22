const express = require('express');
const router = express.Router({ mergeParams: true });
const reviewController = require('../controllers/review.controller');
const { requireAuth } = require('../middleware/auth');
const { uploadReview } = require('../middleware/upload');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
router.param('id', (req, res, next, id) => {
  if (!UUID_RE.test(id)) {
    return res.status(400).json({ message: 'Invalid product id' });
  }
  next();
});

// GET /api/products/:id/reviews (Public list of verified reviews)
router.get('/', reviewController.getProductReviews);

// POST /api/products/:id/reviews (Verified customer review with up to 3 photos)
router.post('/', requireAuth, uploadReview.array('images', 3), reviewController.createReview);

module.exports = router;
