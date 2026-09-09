import "express-session";

// express-session's default SessionData type is empty - we're extending it
// so that req.session.userId is type-checked instead of being `any`.
declare module "express-session" {
  interface SessionData {
    userId?: number;
  }
}