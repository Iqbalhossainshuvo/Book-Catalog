import { paginationHelpers } from '../../../helpers/paginationHelper';
import prisma from '../../../shared/prisma';
import { Book, Prisma } from '@prisma/client';
import { bookSearchableFields } from './book.constant';

const createBook = async (data: Book): Promise<Book> => {
  const result = await prisma.book.create({
    data,
    include: { category: true },
  });
  return result;
};

const getAllBook = async (filters: any, paginationOptions: any) => {
  const { size, page, skip } =
    paginationHelpers.calculatePagination(paginationOptions);
  const { search, minPrice, maxPrice, ...filterData } = filters;

  const andConditions = [];

  if (search) {
    andConditions.push({
      OR: bookSearchableFields.map(field => ({
        [field]: {
          contains: search,
          mode: 'insensitive',
        },
      })),
    });
  }

  if (Object.keys(filterData).length > 0) {
    if (filterData.category) {
      andConditions.push({
        categoryId: filterData.category,
      });
    }
  }

  if (minPrice) {
    andConditions.push({
      price: {
        gte: parseInt(minPrice),
      },
    });
  }
  if (maxPrice) {
    andConditions.push({
      price: {
        lte: parseInt(maxPrice),
      },
    });
  }

  const whereConditions: Prisma.BookWhereInput =
    andConditions.length > 0 ? { AND: andConditions } : {};

  const result = await prisma.book.findMany({
    include: {
      category: true,
    },
    where: whereConditions,
    skip,
    take: size,
    orderBy:
      paginationOptions.sortBy && paginationOptions.sortOrder
        ? { [paginationOptions.sortBy]: paginationOptions.sortOrder }
        : {
            title: 'desc',
          },
  });

  const total = await prisma.book.count({
    where: whereConditions,
  });

  const totalPage = Math.ceil(total / size);

  return {
    meta: {
      total,
      page,
      size,
      totalPage,
    },
    data: result,
  };
};

const getBooksByCategoryId = async (
  paginationOptions: any,
  categoryId: string
) => {
  const { size, page, skip } =
    paginationHelpers.calculatePagination(paginationOptions);

  const result = await prisma.book.findMany({
    where: { categoryId },
    skip,
    take: size,
    orderBy:
      paginationOptions.sortBy && paginationOptions.sortOrder
        ? { [paginationOptions.sortBy]: paginationOptions.sortOrder }
        : {
            title: 'desc',
          },
  });
  const total = await prisma.book.count({
    where: { categoryId },
  });

  const totalPage = Math.ceil(total / size);

  return {
    meta: {
      total,
      page,
      size,
      totalPage,
    },
    data: result,
  };
};

const getSingleBook = async (id: string): Promise<Book | null> => {
  const result = await prisma.book.findUnique({
    where: {
      id,
    },
    include: { category: true },
  });

  return result;
};

const updateBook = async (
  id: string,
  payload: Partial<Book>
): Promise<Book> => {
  const result = await prisma.book.update({
    where: { id },
    data: payload,
    include: { category: true },
  });
  return result;
};

const deleteBook = async (id: string): Promise<Book> => {
  const result = await prisma.book.delete({
    where: {
      id,
    },
  });
  return result;
};

export const BookService = {
  createBook,
  getAllBook,
  getSingleBook,
  getBooksByCategoryId,
  updateBook,
  deleteBook,
};
