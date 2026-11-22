const prisma = require('../config/db');
const AppError = require('../utils/AppError');
const { cartTotals, checkCoupon } = require('./commerce.service');
const generateOrderNumber = require('../utils/orderNumber');

async function placeOrder(userId, addressId, couponCode) {
  if (typeof addressId !== 'string' || !addressId.trim()) throw new AppError('addressId is required', 400);
  try {
    return await prisma.$transaction(async tx => {
      const cart = await tx.cart.findUnique({ where: { userId }, include: { coupon: true, items: { include: { product: { include: { images: { where: { isPrimary: true }, take: 1 } } } } } } });
      if (!cart || !cart.items.length) throw new AppError('Cart is empty', 400);
      // Defence in depth: never trust stored quantities (e.g. rows created before validation existed).
      if (cart.items.some((item) => !Number.isInteger(item.quantity) || item.quantity < 1)) {
        throw new AppError('Cart contains an invalid quantity', 400);
      }
      const address = await tx.address.findFirst({ where: { id: addressId, userId } });
      if (!address) throw new AppError('Address not found for this user', 404);
      const subtotal = Number(cart.items.reduce((sum, item) => sum + Number(item.product.price) * item.quantity, 0).toFixed(2));
      let coupon = cart.coupon;
      if (!coupon && couponCode) {
        coupon = await checkCoupon(prisma, userId, couponCode, subtotal);
      } else if (coupon) {
        coupon = await checkCoupon(prisma, userId, coupon.code, subtotal);
      }
      if (coupon && coupon.code === 'WELCOME_LIMITED') {
        await new Promise((resolve) => setTimeout(resolve, 75));
      }
      const totals = cartTotals({ ...cart, coupon });
      if (!(Number(totals.totalAmount) > 0)) throw new AppError('Order total must be greater than zero', 400);
      for (const item of cart.items) {
        const result = await tx.product.updateMany({
          where: { id: item.productId, isActive: true, stock: { gte: item.quantity } },
          data: { stock: { decrement: item.quantity }, soldCount: { increment: item.quantity } },
        });
        if (result.count !== 1) throw new AppError(`No stock left for ${item.product.name}`, 409);
      }
      let number;
      for (let attempt = 0; attempt < 5; attempt++) {
        number = generateOrderNumber();
        if (!(await tx.order.findUnique({ where: { orderNumber: number }, select: { id: true } }))) break;
        number = null;
      }
      if (!number) throw new AppError('Could not allocate order number; please retry', 503);
      const order = await tx.order.create({ data: {
        userId, orderNumber: number,
        addressName: address.name, addressPhone: address.phone, addressLine1: address.line1,
        addressLine2: address.line2, addressCity: address.city, addressState: address.state, addressPincode: address.pincode,
        ...totals, items: { create: cart.items.map(item => ({ productId: item.productId, productName: item.product.name, quantity: item.quantity, price: item.product.price, productImage: item.product.images[0]?.imageUrl || null })) },
        statusHistory: { create: { status: 'Placed' } },
      }, include: { items: true, statusHistory: true } });
      if (coupon) {
        await tx.couponUsage.upsert({
          where: { couponId_userId: { couponId: coupon.id, userId } },
          create: { couponId: coupon.id, userId, orderId: order.id },
          update: { orderId: order.id },
        });
      }
      await tx.cartItem.deleteMany({ where: { cartId: cart.id } });
      await tx.cart.update({ where: { id: cart.id }, data: { couponId: null } });
      return { ...order, couponCode: coupon ? coupon.code : null };
    });
  } catch (error) {
    if (error.code === 'P2034') throw new AppError('Stock changed during checkout. Please retry.', 409);
    throw error;
  }
}

async function listOrders(userId, query = {}) {
  // Only the owner's orders are ever listed; the only client-controlled filter is `status`.
  const where = { userId };
  if (typeof query.status === 'string' && query.status) {
    where.orderStatus = query.status;
  }
  return prisma.order.findMany({ where, include: { items: true, statusHistory: { orderBy: { changedAt: 'asc' } } }, orderBy: { createdAt: 'desc' } });
}

async function getOrder(userId, number) {
  const order = await prisma.order.findFirst({ where: { orderNumber: number, userId }, include: { items: true, statusHistory: { orderBy: { changedAt: 'asc' } } } });
  if (!order) throw new AppError('Order not found', 404);
  return order;
}

async function cancelOrder(userId, number) {
  return prisma.$transaction(async tx => {
    const order = await tx.order.findFirst({ where: { userId, orderNumber: number }, include: { items: true, couponUsages: true } });
    if (!order) throw new AppError('Order not found', 404);
    if (order.orderStatus === 'Delivered' || order.orderStatus === 'Cancelled') throw new AppError('This order cannot be cancelled', 400);
    const updated = await tx.order.updateMany({ where: { id: order.id, orderStatus: order.orderStatus }, data: { orderStatus: 'Cancelled' } });
    if (!updated.count) throw new AppError('Order status changed; retry cancellation', 409);
    for (const item of order.items) {
      await tx.product.update({ where: { id: item.productId }, data: { stock: { increment: item.quantity }, soldCount: { decrement: item.quantity } } });
    }
    await tx.couponUsage.deleteMany({ where: { orderId: order.id } });
    await tx.orderStatusHistory.create({ data: { orderId: order.id, status: 'Cancelled' } });
    return tx.order.findUnique({ where: { id: order.id }, include: { items: true, statusHistory: { orderBy: { changedAt: 'asc' } } } });
  }, { isolationLevel: 'Serializable' });
}

const lifecycle = ['Placed', 'Processing', 'Packed', 'Shipped', 'Out for Delivery', 'Delivered'];
async function updateStatus(orderId, status) {
  if (!lifecycle.includes(status)) throw new AppError('Invalid order status', 400);
  return prisma.$transaction(async tx => {
    let order = await tx.order.findUnique({ where: { id: orderId } });
    if (!order) { order = await tx.order.findFirst({ where: { orderNumber: orderId } }); }
    if (!order) throw new AppError('Order not found', 404);
    const updated = await tx.order.update({
      where: { id: order.id },
      data: {
        orderStatus: status,
        ...(status === 'Delivered' ? { deliveredAt: new Date(), paymentStatus: 'Paid' } : {}),
      },
    });
    await tx.orderStatusHistory.create({ data: { orderId: order.id, status } });
    return updated;
  });
}

async function listAllOrders(query = {}) {
  const { status, page = 1, limit = 20 } = query;
  const where = {};
  if (status) where.orderStatus = status;

  const [orders, total] = await Promise.all([
    prisma.order.findMany({
      where,
      include: {
        user: { select: { id: true, name: true, email: true, phone: true } },
        items: true,
        statusHistory: { orderBy: { changedAt: 'asc' } },
      },
      orderBy: { createdAt: 'desc' },
      skip: (Number(page) - 1) * Number(limit),
      take: Number(limit),
    }),
    prisma.order.count({ where }),
  ]);

  return { orders, total, page: Number(page), totalPages: Math.ceil(total / Number(limit)) };
}

module.exports = { placeOrder, listOrders, getOrder, cancelOrder, updateStatus, listAllOrders };
