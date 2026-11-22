const prisma = require('../config/db');
const AppError = require('../utils/AppError');

const TEXT_FIELDS = ['name', 'phone', 'line1', 'line2', 'city', 'state', 'pincode', 'country'];

// Address text ends up in orders, invoices and admin screens: never accept markup.
const assertNoMarkup = (data) => {
  for (const field of TEXT_FIELDS) {
    const value = data[field];
    if (value === undefined || value === null) continue;
    if (typeof value !== 'string') throw new AppError(`${field} must be a string`, 400);
    if (value.length > 200) throw new AppError(`${field} is too long`, 400);
    if (/[<>]/.test(value)) throw new AppError(`${field} cannot contain < or > characters`, 400);
  }
};

const getAddresses = async (userId) => {
  return await prisma.address.findMany({
    where: { userId },
    orderBy: [{ isDefault: 'desc' }, { createdAt: 'desc' }],
  });
};

const createAddress = async (userId, data) => {
  assertNoMarkup(data);
  const { name, phone, line1, line2, city, state, pincode, country = 'India', addressType = 'home', isDefault = false } = data;

  if (!name || !phone || !line1 || !city || !state || !pincode) {
    throw new AppError('Name, phone, line1, city, state, and pincode are required', 400);
  }

  return await prisma.$transaction(async (tx) => {
    if (isDefault) {
      await tx.address.updateMany({
        where: { userId, isDefault: true },
        data: { isDefault: false },
      });
    }

    return await tx.address.create({
      data: {
        userId,
        name: name.trim(),
        phone: phone.trim(),
        line1: line1.trim(),
        line2: line2?.trim() || null,
        city: city.trim(),
        state: state.trim(),
        pincode: pincode.trim(),
        country: country?.trim() || 'India',
        addressType: addressType || 'home',
        isDefault: Boolean(isDefault),
      },
    });
  });
};

const updateAddress = async (userId, addressId, data) => {
  assertNoMarkup(data);
  const existing = await prisma.address.findFirst({
    where: { id: addressId, userId },
  });

  if (!existing) {
    throw new AppError('Address not found', 404);
  }

  return await prisma.$transaction(async (tx) => {
    if (data.isDefault) {
      await tx.address.updateMany({
        where: { userId, isDefault: true },
        data: { isDefault: false },
      });
    }

    return await tx.address.update({
      where: { id: addressId },
      data: {
        name: data.name !== undefined ? data.name.trim() : undefined,
        phone: data.phone !== undefined ? data.phone.trim() : undefined,
        line1: data.line1 !== undefined ? data.line1.trim() : undefined,
        line2: data.line2 !== undefined ? data.line2.trim() : undefined,
        city: data.city !== undefined ? data.city.trim() : undefined,
        state: data.state !== undefined ? data.state.trim() : undefined,
        pincode: data.pincode !== undefined ? data.pincode.trim() : undefined,
        country: data.country !== undefined ? data.country.trim() : undefined,
        addressType: data.addressType || undefined,
        isDefault: data.isDefault !== undefined ? Boolean(data.isDefault) : undefined,
      },
    });
  });
};

const deleteAddress = async (userId, addressId) => {
  const existing = await prisma.address.findFirst({
    where: { id: addressId, userId },
  });

  if (!existing) {
    throw new AppError('Address not found', 404);
  }

  return await prisma.address.delete({
    where: { id: addressId },
  });
};

module.exports = {
  getAddresses,
  createAddress,
  updateAddress,
  deleteAddress,
};
