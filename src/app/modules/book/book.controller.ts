import httpStatus from 'http-status';
import sendResponse from '../../../shared/sendResponse';
import { BookService } from './book.service';
import { Request, Response } from 'express';
import catchAsync from '../../../shared/catchAsync';
import pick from '../../../shared/pick';
import { bookFilterableFields } from './book.constant';

const createBook = catchAsync(async (req: Request, res: Response) => {
  const result = await BookService.createBook(req.body);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Book created successfully',
    data: result,
  });
});

const getAllBook = catchAsync(async (req: Request, res: Response) => {
  const filters = pick(req.query, bookFilterableFields);
  const paginationOptions = pick(req.query, [
    'size',
    'page',
    'sortBy',
    'sortOrder',
  ]);

  const result = await BookService.getAllBook(filters, paginationOptions);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'All book fetched successfully',
    meta: result.meta,
    data: result.data,
  });
});

const getBooksByCategoryId = catchAsync(async (req: Request, res: Response) => {
  const { categoryId } = req.params;
  const paginationOptions = pick(req.query, [
    'size',
    'page',
    'sortBy',
    'sortOrder',
  ]);
  const result = await BookService.getBooksByCategoryId(
    paginationOptions,
    categoryId
  );
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'All book fetched successfully',
    meta: result.meta,
    data: result.data,
  });
});

const getSingleBook = catchAsync(async (req: Request, res: Response) => {
  const { id } = req.params;
  const result = await BookService.getSingleBook(id);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Book fetched successfully',
    data: result,
  });
});

const updateBook = catchAsync(async (req: Request, res: Response) => {
  const { id } = req.params;
  const payload = req.body;
  const result = await BookService.updateBook(id, payload);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Book updated successfully',
    data: result,
  });
});

const deleteBook = catchAsync(async (req: Request, res: Response) => {
  const { id } = req.params;
  const result = await BookService.deleteBook(id);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Book deleted successfully',
    data: result,
  });
});

export const BookController = {
  createBook,
  getAllBook,
  getSingleBook,
  getBooksByCategoryId,
  updateBook,
  deleteBook,
};
