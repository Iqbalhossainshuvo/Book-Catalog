import { Request, Response } from 'express';
import sendResponse from '../../../shared/sendResponse';
import httpStatus from 'http-status';
import { OrderService } from './order.service';
import catchAsync from '../../../shared/catchAsync';


const createOrder = catchAsync(async (req, res) => {
  const result = await OrderService.createOrder(req.body.user, req.body.payload);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Order created successfully',
    data: result,
  });
});





const getAllOrder = catchAsync(async (req: Request, res: Response) => {
  const result = await OrderService.getAllOrder(req.user);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Order fetched successfully',
    data: result,
  });
});

const getSingleOrder = catchAsync(async (req: Request, res: Response) => {
  const { orderId } = req.params;
  const result = await OrderService.getSingleOrder(req.user, orderId);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Single Order fetched successfully',
    data: result,
  });
});

export const OrderController = {
  createOrder,
  getAllOrder,
  getSingleOrder,
};
