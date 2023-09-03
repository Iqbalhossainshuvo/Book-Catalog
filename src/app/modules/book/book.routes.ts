import express from 'express';
import auth from '../../middlewares/auth';
import { ENUM_USER_ROLE } from '../../../enums/user';
import { BookController } from './book.controller';
const router = express.Router();

router.post(
  '/create-book',
   auth(ENUM_USER_ROLE.ADMIN),
  BookController.createBook
);

router.get('/', BookController.getAllBook);

router.get('/:categoryId/category', BookController.getBooksByCategoryId);

router.get('/:id', BookController.getSingleBook);

router.patch('/:id', auth(ENUM_USER_ROLE.ADMIN), BookController.updateBook);

router.delete('/:id', auth(ENUM_USER_ROLE.ADMIN), BookController.deleteBook);

export const BookRoutes = router;
