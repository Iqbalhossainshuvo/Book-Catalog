import { Request, Response } from 'express';
import catchAsync from '../../../shared/catchAsync';
import { ProfileService } from './profile.service';
import sendResponse from '../../../shared/sendResponse';
import httpStatus from 'http-status';

const getProfile = catchAsync(async (req: Request, res: Response) => {
  const result = await ProfileService.getProfile(req.user);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Profile fetched successfully',
    data: result,
  });
});

export const ProfileController = {
  getProfile,
};
