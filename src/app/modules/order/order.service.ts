import prisma from '../../../shared/prisma';
import ApiError from '../../../errors/ApiError';
import httpStatus from 'http-status';
import { Order } from '@prisma/client';

const createOrder = async (user:any, payload:any):Promise<Order> => {
  // Check if the user object is defined
  if (!user) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'User not provided');
  }

  // Destructure userId and role if the user object exists
  const { userId, role } = user;

  const isExist = await prisma.user.findUnique({ where: { id: userId } });

  if (!isExist) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }

  if (role !== 'customer') {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Only customers can order');
  }

  const { orderedBooks } = payload;

  const result = await prisma.order.create({
    data: {
      userId: userId,
      orderedBooks,
    },
  });
  return result;
};



const getAllOrder = async (user: any) => {
  const { userId, role } = user;

  const isExist = await prisma.user.findUnique({ where: { id: userId } });

  if (!isExist) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }

  if (role === 'admin') {
    const result = await prisma.order.findMany({});
    return result;
  }
  if (role === 'customer') {
    const result = await prisma.order.findMany({ where: { userId: userId } });

    return result;
  }
};

const getSingleOrder = async (user: any, orderId: string) => {
  const { role, userId } = user;

  const isExist = await prisma.user.findUnique({ where: { id: userId } });

  if (!isExist) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }
  if (role === 'admin') {
    const result = await prisma.order.findUnique({ where: { id: orderId } });
    return result;
  }
  if (role === 'customer') {
    const result = await prisma.order.findUnique({
      where: { id: orderId, userId },
    });
    return result;
  }
};

export const OrderService = {
  createOrder,
  getAllOrder,
  getSingleOrder,
};
