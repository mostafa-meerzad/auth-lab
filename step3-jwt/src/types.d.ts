// We'll attach the decoded token payload onto req.user after verification,
// so route handlers can read "who is this" without re-verifying anything.
export interface JwtPayload {
  userId: number;
  email: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload;
    }
  }
}

export {};