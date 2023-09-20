import { User } from '@prisma/client';
import prisma from '../../../shared/prisma';
import bcrypt from 'bcrypt';
import config from '../../../config';
import { ILoginUser } from './auth.interface';
import ApiError from '../../../errors/ApiError';
import httpStatus from 'http-status';
import { jwtHelpers } from '../../../helpers/jwtHelpers';
import { Secret } from 'jsonwebtoken';

const createUser = async (data: User): Promise<User> => {
  const { password, ...others } = data;
  const hashedPassword = await bcrypt.hash(
    password,
    Number(config.bcrypt_salt_rounds)
  );
  const result = await prisma.user.create({
    data: {
      password: hashedPassword,
      ...others,
    },
  });
  return result;
};

// const loginUser = async (payload: ILoginUser) => {
//   const { email, password } = payload;

//   const isUserExist = await prisma.user.findFirst({ where: { email: email } });
//   if (!isUserExist) {
//     throw new ApiError(httpStatus.NOT_FOUND, 'User does not exist');
//   }

//   const isPasswordMatch = await bcrypt.compare(password, isUserExist.password);
//   if (!isPasswordMatch) {
//     throw new ApiError(httpStatus.NOT_FOUND, 'Password is incorrect');
//   }

//   const { id: userId, role } = isUserExist;

//   const accessToken = jwtHelpers.createToken(
//     { userId, role },
//     config.jwt.secret as Secret,
//     config.jwt.expires_in as string
//   );

//   return accessToken;
// };
const loginUser = async (payload: ILoginUser) => {
  const { email, password } = payload;

  const isUserExist = await prisma.user.findFirst({ where: { email: email } });
  if (!isUserExist) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User does not exist');
  }

  const isPasswordMatch = await bcrypt.compare(password, isUserExist.password);
  if (!isPasswordMatch) {
    throw new ApiError(httpStatus.NOT_FOUND, 'Password is incorrect');
  }

  const { id: userId, role } = isUserExist;

  // Assuming config.jwt.expires_in is set correctly
  const expiresIn = config.jwt.expires_in;

  const accessToken = jwtHelpers.createToken(
    { userId, role },
    config.jwt.secret as Secret,
    expiresIn!
  );

  return accessToken;
};


export const AuthService = {
  createUser,
  loginUser,
};
