const prisma = require('../config/db');
const AppError = require('../utils/AppError');

/**
 * Helper: Recalculates product avgRating and reviewCount
 * Excludes reviews with reviewStatus = 'Removed'
 */
const recalculateProductRating = async (productId, tx = prisma) => {
  const activeReviews = await tx.review.findMany({
    where: {
      productId,
      reviewStatus: { not: 'Removed' },
    },
    select: { rating: true },
  });

  const reviewCount = activeReviews.length;
  const avg = reviewCount > 0
    ? activeReviews.reduce((sum, r) => sum + r.rating, 0) / reviewCount
    : 0.0;

  await tx.product.update({
    where: { id: productId },
    data: {
      avgRating: parseFloat(avg.toFixed(2)),
      reviewCount,
    },
  });
};

// Reviews are shown to every shopper: strip any HTML tags before storing.
// (A bare "<3" or "a < b" is preserved; only tag-like sequences are removed.)
const cleanComment = (comment) =>
  String(comment).replace(/<\/?[a-zA-Z!][^>]*>?/g, '').trim();

/**
 * Post a new verified review
 */
const createReview = async ({ productId, userId, rating, comment, files = [] }) => {
  const numericRating = parseInt(rating, 10);
  if (isNaN(numericRating) || numericRating < 1 || numericRating > 5) {
    throw new AppError('Rating must be an integer between 1 and 5', 400);
  }

  if (typeof comment !== 'string' || cleanComment(comment).length === 0) {
    throw new AppError('Review comment is required', 400);
  }
  if (comment.length > 2000) {
    throw new AppError('Review comment is too long', 400);
  }
  comment = cleanComment(comment);

  // 1. Check if user already reviewed this product (upsert)
  const existingReview = await prisma.review.findUnique({
    where: {
      userId_productId: {
        userId,
        productId,
      },
    },
  });

  if (existingReview) {
    return prisma.$transaction(async (tx) => {
      const review = await tx.review.update({
        where: { id: existingReview.id },
        data: {
          rating: numericRating,
          comment: comment.trim(),
        },
      });

      if (files.length > 0) {
        await tx.reviewImage.deleteMany({ where: { reviewId: review.id } });
        await tx.reviewImage.createMany({
          data: files.map((file) => ({
            reviewId: review.id,
            imageUrl: `/uploads/${file.filename}`,
          })),
        });
      }

      await recalculateProductRating(productId, tx);
      return tx.review.findUnique({
        where: { id: review.id },
        include: {
          images: true,
          user: { select: { name: true } },
        },
      });
    });
  }

  // 2. Verified Purchaser Check: User must have a Delivered order with this product
  const verifiedOrder = await prisma.order.findFirst({
    where: {
      userId,
      orderStatus: 'Delivered',
      items: {
        some: {
          productId,
        },
      },
    },
  });

  if (!verifiedOrder) {
    throw new AppError('Only verified purchasers can review this product', 403);
  }

  // Max 3 images
  if (files.length > 3) {
    throw new AppError('You can upload a maximum of 3 photos with your review', 400);
  }

  // 3. Create review, save images, and recalculate ratings atomically
  return prisma.$transaction(async (tx) => {
    const review = await tx.review.create({
      data: {
        productId,
        userId,
        rating: numericRating,
        comment: comment.trim(),
        reviewStatus: 'Active',
      },
    });

    if (files.length > 0) {
      await tx.reviewImage.createMany({
        data: files.map((file) => ({
          reviewId: review.id,
          imageUrl: `/uploads/${file.filename}`,
        })),
      });
    }

    await recalculateProductRating(productId, tx);

    return tx.review.findUnique({
      where: { id: review.id },
      include: {
        images: true,
        user: { select: { name: true } },
      },
    });
  });
};

/**
 * Edit an existing review (owner only)
 */
const updateReview = async ({ reviewId, userId, rating, comment }) => {
  const review = await prisma.review.findUnique({
    where: { id: reviewId },
  });

  if (!review) {
    throw new AppError('Review not found', 404);
  }

  if (review.userId !== userId) {
    throw new AppError('You are not authorized to edit this review', 403);
  }

  const data = {};
  if (rating !== undefined) {
    const numericRating = parseInt(rating, 10);
    if (isNaN(numericRating) || numericRating < 1 || numericRating > 5) {
      throw new AppError('Rating must be an integer between 1 and 5', 400);
    }
    data.rating = numericRating;
  }

  if (comment !== undefined) {
    if (typeof comment !== 'string') throw new AppError('Review comment must be text', 400);
    comment = cleanComment(comment);
    if (comment.length === 0) {
      throw new AppError('Comment cannot be empty', 400);
    }
    data.comment = comment.trim();
  }

  return prisma.$transaction(async (tx) => {
    const updatedReview = await tx.review.update({
      where: { id: reviewId },
      data,
      include: { images: true },
    });

    await recalculateProductRating(review.productId, tx);
    return updatedReview;
  });
};

/**
 * Delete a review (owner or admin)
 */
const deleteReview = async ({ reviewId, user }) => {
  const review = await prisma.review.findUnique({
    where: { id: reviewId },
  });

  if (!review) {
    throw new AppError('Review not found', 404);
  }

  if (user.role !== 'admin' && review.userId !== user.id) {
    throw new AppError('You are not authorized to delete this review', 403);
  }

  await prisma.$transaction(async (tx) => {
    await tx.review.delete({
      where: { id: reviewId },
    });
    await recalculateProductRating(review.productId, tx);
  });

  return { message: 'Review deleted successfully' };
};

/**
 * Public: Get reviews for a specific product
 */
const getProductReviews = async ({ productId, page = 1, limit = 10 }) => {
  const skip = (parseInt(page, 10) - 1) * parseInt(limit, 10);
  const take = parseInt(limit, 10);

  const where = {
    productId,
    reviewStatus: { not: 'Removed' },
  };

  const [reviews, total] = await Promise.all([
    prisma.review.findMany({
      where,
      skip,
      take,
      include: {
        user: { select: { name: true } },
        images: true,
      },
      orderBy: { createdAt: 'desc' },
    }),
    prisma.review.count({ where }),
  ]);

  return {
    reviews,
    total,
    page: parseInt(page, 10),
    pages: Math.ceil(total / take),
  };
};

/**
 * Customer reports an abusive review
 */
const reportReview = async ({ reviewId, userId, reportReason }) => {
  if (!reportReason || reportReason.trim().length === 0) {
    throw new AppError('Report reason is required', 400);
  }

  const review = await prisma.review.findUnique({
    where: { id: reviewId },
  });

  if (!review) {
    throw new AppError('Review not found', 404);
  }

  if (review.userId === userId) {
    throw new AppError('You cannot report your own review', 400);
  }

  const existingReport = await prisma.reportReview.findUnique({
    where: {
      reviewId_userId: {
        reviewId,
        userId,
      },
    },
  });

  if (existingReport) {
    throw new AppError('You have already reported this review', 409);
  }

  return prisma.$transaction(async (tx) => {
    const report = await tx.reportReview.create({
      data: {
        reviewId,
        userId,
        reportReason: reportReason.trim(),
        reportStatus: 'Pending',
      },
    });

    // Do not automatically unpublish review on single user report; keep Active for admin moderation
    return report;
  });
};

/**
 * Admin: Get flagged and reported reviews queue
 */
const adminGetReportedReviews = async ({ page = 1, limit = 20 }) => {
  const skip = (parseInt(page, 10) - 1) * parseInt(limit, 10);
  const take = parseInt(limit, 10);

  const where = {
    reports: {
      some: { reportStatus: 'Pending' },
    },
  };

  const [reviews, total] = await Promise.all([
    prisma.review.findMany({
      where,
      skip,
      take,
      include: {
        product: { select: { id: true, name: true } },
        user: { select: { name: true, email: true } },
        images: true,
        reports: {
          where: { reportStatus: 'Pending' },
          include: {
            user: { select: { name: true, email: true } },
          },
        },
      },
      orderBy: { updatedAt: 'desc' },
    }),
    prisma.review.count({ where }),
  ]);

  return {
    reviews,
    total,
    page: parseInt(page, 10),
    pages: Math.ceil(total / take),
  };
};

/**
 * Admin: Dismiss report (restore review to Active)
 */
const adminDismissReport = async ({ reviewId, adminId, reason = 'Report dismissed by moderator' }) => {
  const review = await prisma.review.findUnique({ where: { id: reviewId } });
  if (!review) throw new AppError('Review not found', 404);

  return prisma.$transaction(async (tx) => {
    // 1. Restore review status to Active
    const updatedReview = await tx.review.update({
      where: { id: reviewId },
      data: { reviewStatus: 'Active' },
    });

    // 2. Dismiss all pending reports
    await tx.reportReview.updateMany({
      where: { reviewId, reportStatus: 'Pending' },
      data: { reportStatus: 'Dismissed' },
    });

    // 3. Record moderation audit trail
    await tx.reviewModeration.create({
      data: {
        adminId,
        reviewId,
        action: 'Dismissed',
        reason,
      },
    });

    return updatedReview;
  });
};

/**
 * Admin: Remove abusive review (soft removal, recalculates product rating)
 */
const adminRemoveReview = async ({ reviewId, adminId, reason = 'Violates community guidelines' }) => {
  const review = await prisma.review.findUnique({ where: { id: reviewId } });
  if (!review) throw new AppError('Review not found', 404);

  return prisma.$transaction(async (tx) => {
    // 1. Set review status to Removed (hidden from customer view)
    const updatedReview = await tx.review.update({
      where: { id: reviewId },
      data: { reviewStatus: 'Removed' },
    });

    // 2. Mark all reports as Resolved
    await tx.reportReview.updateMany({
      where: { reviewId, reportStatus: 'Pending' },
      data: { reportStatus: 'Resolved' },
    });

    // 3. Record moderation audit trail
    await tx.reviewModeration.create({
      data: {
        adminId,
        reviewId,
        action: 'Removed',
        reason,
      },
    });

    // 4. Recalculate product rating to exclude this removed review
    await recalculateProductRating(review.productId, tx);

    return updatedReview;
  });
};

module.exports = {
  createReview,
  updateReview,
  deleteReview,
  getProductReviews,
  reportReview,
  adminGetReportedReviews,
  adminDismissReport,
  adminRemoveReview,
  recalculateProductRating,
};
