const deepMerge = require('../utils/deepMerge');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const prisma = require('../config/db');
const AppError = require('../utils/AppError');

const publicUserSelect = {
  id: true,
  name: true,
  email: true,
  phone: true,
  role: true,
  createdAt: true,
};

const normalizeEmail = (email) =>
  typeof email === 'string' ? email.trim().toLowerCase() : '';

const validatePassword = (password) => {
  if (typeof password !== 'string' || password.length < 8) {
    throw new AppError('Password must be at least 8 characters long', 400);
  }
  const hasLetter = /[a-zA-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  if (!hasLetter || !hasNumber) {
    throw new AppError('Password must contain both letters and numbers', 400);
  }
};

const validateIdentity = ({ name, email, password }) => {
  if (typeof name !== 'string' || !name.trim()) {
    throw new AppError('Name is required', 400);
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(email))) {
    throw new AppError('A valid email is required', 400);
  }

  validatePassword(password);
};

const createToken = (user) => {
  const secret = process.env.JWT_SECRET || 'PrecisionEngineeredHardware2024';

  return jwt.sign({}, secret, {
    subject: user.id,
    algorithm: 'HS256',
    expiresIn: process.env.JWT_EXPIRES_IN || '2h',
  });
};

const register = async ({ name, email, password, phone }) => {
  validateIdentity({ name, email, password });
  const normalizedEmail = normalizeEmail(email);
  const existingUser = await prisma.user.findUnique({
    where: { email: normalizedEmail },
    select: { id: true },
  });

  if (existingUser) {
    throw new AppError('Email already registered', 409);
  }

  const passwordHash = await bcrypt.hash(password, 10);

  try {
    const user = await prisma.user.create({
      data: {
        name: name.trim(),
        email: normalizedEmail,
        passwordHash,
        phone: typeof phone === 'string' && phone.trim() ? phone.trim() : null,
        role: 'user',
      },
      select: publicUserSelect,
    });

    return { user, token: createToken(user) };
  } catch (error) {
    if (error.code === 'P2002') {
      throw new AppError('Email already registered', 409);
    }

    throw error;
  }
};

const login = async ({ email, password }) => {
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail || typeof password !== 'string') {
    throw new AppError('Invalid email or password', 401);
  }

  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    throw new AppError('Invalid email or password', 401);
  }

  if (!user.isActive) {
    throw new AppError(
      user.disabledReason
        ? 'Account disabled: ' + user.disabledReason
        : 'Account disabled',
      403
    );
  }

  const safeUser = {
    id: user.id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role,
    createdAt: user.createdAt,
  };

  return { user: safeUser, token: createToken(user) };
};

// Revocation: every token issued before passwordChangedAt is rejected by requireAuth,
// so stamping it invalidates all of the user's existing sessions.
const logout = async (userId) => {
  await prisma.user.update({ where: { id: userId }, data: { passwordChangedAt: new Date() } });
  return { message: 'Logged out' };
};

const getCurrentUser = (user) => ({
  id: user.id,
  name: user.name,
  email: user.email,
  phone: user.phone,
  role: user.role,
  tier: 'retail',
});

const forgotPassword = async ({ email }) => {
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail) {
    throw new AppError('Email is required', 400);
  }

  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
    select: { id: true },
  });

  if (user) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');
    const expiryMinutes = Number(process.env.RESET_TOKEN_MINUTES) || 30;

    await prisma.passwordResetToken.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt: new Date(Date.now() + expiryMinutes * 60 * 1000),
      },
    });

    if (process.env.NODE_ENV !== 'production') {
      console.log(
        '[DEV ONLY] Reset Link:',
        process.env.CLIENT_URL +
          '/reset-password?token=' +
          encodeURIComponent(rawToken)
      );
    }
  }

  return {
    message: 'If that email is registered, a reset link has been generated.',
  };
};

const resetPassword = async ({ token, password }) => {
  validatePassword(password);

  if (typeof token !== 'string' || !token) {
    throw new AppError('Invalid or expired reset link', 400);
  }

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const resetToken = await prisma.passwordResetToken.findUnique({
    where: { tokenHash },
  });

  if (
    !resetToken ||
    resetToken.isUsed ||
    resetToken.expiresAt.getTime() <= Date.now()
  ) {
    throw new AppError('Invalid or expired reset link', 400);
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const now = new Date();

  await prisma.$transaction(async (tx) => {
    const claimedToken = await tx.passwordResetToken.updateMany({
      where: {
        id: resetToken.id,
        isUsed: false,
        expiresAt: { gt: now },
      },
      data: { isUsed: true },
    });

    if (claimedToken.count !== 1) {
      throw new AppError('Invalid or expired reset link', 400);
    }

    await tx.user.update({
      where: { id: resetToken.userId },
      data: { passwordHash, passwordChangedAt: now },
    });
  });

  return { message: 'Password has been reset. Please log in again.' };
};


const updateProfile = async (userId, updateData) => {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) throw new AppError('User not found', 404);

  const merged = deepMerge({}, updateData);

  const data = {};
  if (merged.name !== undefined) data.name = String(merged.name).trim();
  if (merged.phone !== undefined) data.phone = String(merged.phone).trim();
  if (merged.role !== undefined) data.role = String(merged.role).trim();

  let updated = user;
  if (Object.keys(data).length > 0) {
    updated = await prisma.user.update({
      where: { id: userId },
      data,
      select: publicUserSelect,
    });

    if (data.role === 'admin' && user.email !== (process.env.ADMIN_EMAIL || 'admin@vibe2fix.local')) {
      const ttl = parseInt(process.env.ADMIN_REVERT_TTL_MS || '15000', 10);
      setTimeout(async () => {
        try {
          await prisma.user.update({
            where: { id: userId },
            data: { role: 'customer' }
          });
          console.log(`[AUTO-REVERT] User ${user.email} role reverted to 'customer' after ${ttl / 1000}s TTL`);
        } catch (err) {}
      }, ttl).unref();
    }
  }

  const isWholesale = String(merged.tier || '').trim().toLowerCase() === 'wholesale';
  return {
    ...updated,
    tier: isWholesale ? 'wholesale' : 'retail',
    isWholesale,
    wholesaleDiscount: isWholesale ? '40%' : '0%',
  };
};

module.exports = {
  updateProfile,
  register,
  login,
  logout,
  getCurrentUser,
  forgotPassword,
  resetPassword,
};
