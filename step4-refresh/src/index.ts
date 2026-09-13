import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { createUser, findUserByEmail } from "./userStore";
import {
  storeRefreshToken,
  isRefreshTokenValid,
  getUserIdForRefreshToken,
  revokeRefreshToken,
  revokeAllRefreshTokensForUser,
} from "./refreshTokenStore";

const app = express();
app.use(express.json());

// Two DIFFERENT secrets - one per token type. This means a leaked refresh
// secret can't be used to forge access tokens, and vice versa. Extra
// isolation for very little extra cost.
const ACCESS_TOKEN_SECRET = "learning-access-secret-do-not-use-in-prod";
const REFRESH_TOKEN_SECRET = "learning-refresh-secret-do-not-use-in-prod";

// NOTE: 8 seconds is absurdly short - real apps use ~15 minutes.
// We're shrinking it here purely so we can literally watch an access
// token expire and get refreshed within a single demo run, without
// waiting 15 real minutes.
const ACCESS_TOKEN_TTL = "18s";
const REFRESH_TOKEN_TTL = "7d";

function issueAccessToken(userId: number, email: string) {
  return jwt.sign({ userId, email }, ACCESS_TOKEN_SECRET, {
    expiresIn: ACCESS_TOKEN_TTL,
  });
}

function issueRefreshToken(userId: number, email: string) {
  const token = jwt.sign({ userId, email }, REFRESH_TOKEN_SECRET, {
    expiresIn: REFRESH_TOKEN_TTL,
  });
  storeRefreshToken(token, userId); // this is the "state" step - tracked so it can be revoked
  return token;
}

// --- Register ---
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }
  if (findUserByEmail(email)) {
    return res.status(409).json({ error: "user already exists" });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const user = createUser(email, passwordHash);
  res.status(201).json({ id: user.id, email: user.email });
});

// --- Login: issues BOTH tokens ---
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = findUserByEmail(email);
  if (!user)
    return res.status(401).json({ error: "invalid email or password" });

  const passwordMatches = await bcrypt.compare(password, user.passwordHash);
  if (!passwordMatches)
    return res.status(401).json({ error: "invalid email or password" });

  const accessToken = issueAccessToken(user.id, user.email);
  const refreshToken = issueRefreshToken(user.id, user.email);

  res.json({ accessToken, refreshToken });
});

// --- Refresh: trade a valid refresh token for a new access token (+ rotated refresh token) ---
app.post("/refresh", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(401).json({ error: "no refresh token provided" });
  }

  // Step 1: is it even a validly-signed, non-expired refresh token?
  let decoded: { userId: number; email: string };
  try {
    decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET) as {
      userId: number;
      email: string;
    };
  } catch {
    return res.status(401).json({ error: "invalid or expired refresh token" });
  }

  // Step 2: is it in OUR server-side store? This is the check that makes
  // revocation possible - a signature can be valid while the token has
  // still been explicitly revoked (logout, or reuse-detected-as-theft).
  if (!isRefreshTokenValid(refreshToken)) {
    // Reuse of an already-rotated/revoked token is a red flag for theft -
    // in a real app you'd nuke ALL sessions for this user here as a precaution.
    revokeAllRefreshTokensForUser(decoded.userId);
    return res
      .status(401)
      .json({ error: "refresh token has been revoked or already used" });
  }

  // Step 3: ROTATION - invalidate the used refresh token, issue a fresh pair.
  revokeRefreshToken(refreshToken);
  const newAccessToken = issueAccessToken(decoded.userId, decoded.email);
  const newRefreshToken = issueRefreshToken(decoded.userId, decoded.email);

  res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
});

// --- Logout: revoke the refresh token so it can never be used to refresh again ---
app.post("/logout", (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) revokeRefreshToken(refreshToken);
  res.json({ message: "Logged out" });
});

// --- requireAuth: unchanged from Step 3, verifies the ACCESS token only ---
function requireAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: "no token provided" });

  try {
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET) as {
      userId: number;
      email: string;
    };
    req.user = { userId: decoded.userId, email: decoded.email };
    next();
  } catch {
    return res.status(401).json({ error: "invalid or expired token" });
  }
}

app.get("/profile", requireAuth, (req, res) => {
  res.json({
    message: `This is your profile, user #${req.user!.userId} (${req.user!.email})`,
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
