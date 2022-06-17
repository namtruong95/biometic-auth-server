import { NextFunction, Request, Response } from 'express';
import { CustomHeadersEnum } from '../types/common';

export const authFingerprint = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const userEmail = req.header(CustomHeadersEnum.userEmail);

  if (!userEmail) {
    res.status(401).json({ error: 'Missing user email' });
  }
  res.locals.userEmail = userEmail;

  const challenge = req.header(CustomHeadersEnum.challenge);

  res.locals.challenge = challenge;

  const origin = req.header('origin') || '';
  const url = new URL(origin);

  res.locals.hostname = url.hostname;
  res.locals.origin = origin;

  next();
};
