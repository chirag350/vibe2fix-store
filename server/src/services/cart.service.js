const prisma = require('../config/db');
const AppError = require('../utils/AppError');
const { cartTotals, getOrCreateCart, checkCoupon } = require('./commerce.service');

const cartInclude = { coupon: true, items: { include: { product: { include: { images: { where: { isPrimary: true }, take: 1 } } } } } };

async function getCart(userId) {
  const cart = await getOrCreateCart(prisma, userId);
  const full = await prisma.cart.findUnique({ where: { id: cart.id }, include: cartInclude });
  const items = full.items.map(({ product, ...item }) => ({ ...item, product, isAvailable: product.isActive && product.stock >= item.quantity }));
  return { id: full.id, items, coupon: full.coupon, ...cartTotals(full) };
}

const MAX_LINE_QUANTITY = 1000;
const assertValidQuantity = (quantity) => {
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > MAX_LINE_QUANTITY) {
    throw new AppError(`Quantity must be an integer between 1 and ${MAX_LINE_QUANTITY}`, 400);
  }
};

async function addToCart(userId, productId, quantity = 1) {
  quantity = Number(quantity);
  assertValidQuantity(quantity);
  const product = await prisma.product.findUnique({ where: { id: productId } });
  if (!product || !product.isActive) throw new AppError('Product not found or unavailable', 404);
  const cart = await getOrCreateCart(prisma, userId);
  const current = await prisma.cartItem.findUnique({ 
    where: { cartId_productId: { cartId: cart.id, productId } } 
  });
  const nextQty = (current?.quantity || 0) + quantity;
  if (nextQty > product.stock) throw new AppError('Requested quantity exceeds available stock', 409);
  await prisma.cartItem.upsert({ 
    where: { cartId_productId: { cartId: cart.id, productId } }, 
    create: { cartId: cart.id, productId, quantity }, 
    update: { quantity: nextQty } 
  });
  return getCart(userId);
}

async function updateQuantity(userId, productId, quantity) {
  quantity = Number(quantity);
  assertValidQuantity(quantity);
  const cart = await getOrCreateCart(prisma, userId);
  const product = await prisma.product.findUnique({ where: { id: productId } });
  if (!product || !product.isActive) throw new AppError('Product not found or unavailable', 404);
  if (quantity > product.stock) throw new AppError('Requested quantity exceeds available stock', 409);
  const result = await prisma.cartItem.updateMany({ where: { cartId: cart.id, productId }, data: { quantity } });
  if (!result.count) throw new AppError('Cart item not found', 404);
  return getCart(userId);
}

async function removeItem(userId, productId) {
  const cart = await getOrCreateCart(prisma, userId);
  const result = await prisma.cartItem.deleteMany({ where: { cartId: cart.id, productId } });
  if (!result.count) throw new AppError('Cart item not found', 404);
  return getCart(userId);
}

async function applyCoupon(userId, code) {
  const cart = await getOrCreateCart(prisma, userId);
  const full = await prisma.cart.findUnique({ where: { id: cart.id }, include: cartInclude });
  const subtotal = cartTotals(full).subtotal;
  const coupon = await checkCoupon(prisma, userId, code, subtotal);
  await prisma.cart.update({ where: { id: cart.id }, data: { couponId: coupon.id } });
  return getCart(userId);
}

async function removeCoupon(userId) {
  const cart = await getOrCreateCart(prisma, userId);
  await prisma.cart.update({ where: { id: cart.id }, data: { couponId: null } });
  return getCart(userId);
}

module.exports = { getCart, addToCart, updateQuantity, removeItem, applyCoupon, removeCoupon };
