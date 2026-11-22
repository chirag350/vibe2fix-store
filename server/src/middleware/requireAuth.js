const jwt = require('jsonwebtoken');
const prisma = require('../config/db');
const AppError = require('../utils/AppError');
const asyncHandler = require('../utils/asyncHandler');

const requireAuth = asyncHandler(async (req, res, next) => {
  const authorization = req.headers.authorization || '';
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : null;

  if (!token) {
    throw new AppError('Authentication required. Please log in.', 401);
  }

  const secret = require('../utils/jwtSecret');
  let payload;

  try {
    payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
  } catch (err) {
    throw new AppError('Invalid or expired authentication token', 401);
  }

  const userId = payload.sub || payload.id || payload.userId;
  if (!userId) {
    throw new AppError('Malformed token payload', 401);
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      name: true,
      email: true,
      phone: true,
      role: true,
      isActive: true,
      disabledReason: true,
      passwordChangedAt: true,
    },
  });

  if (!user) {
    throw new AppError('User not found. Please log in again.', 401);
  }

  if (!user.isActive) {
    throw new AppError(
      user.disabledReason ? `Account disabled: ${user.disabledReason}` : 'Account disabled',
      403
    );
  }

  if (
    user.passwordChangedAt &&
    payload.iat &&
    Math.floor(user.passwordChangedAt.getTime() / 1000) >= payload.iat
  ) {
    throw new AppError('Password recently changed. Please log in again.', 401);
  }

  req.user = user;
  next();
});

module.exports = requireAuth;
