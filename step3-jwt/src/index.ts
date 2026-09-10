import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { createUser, findUserByEmail } from "./userStore";
// Note: no import needed for ./types.d.ts - TypeScript picks up ambient
// global declarations automatically since it's included via tsconfig.
// (Declaration files are type-only and have nothing to run at runtime.)

const app = express();
app.use(express.json());

// In a real app this comes from an environment variable, never hardcoded.
// This is the ONE secret both signing and verifying rely on.
const JWT_SECRET = "learning-jwt-secret-do-not-use-in-prod";

// --- Register (unchanged from the session version - hashing is identical) ---
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

// --- Login ---
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = findUserByEmail(email);
  if (!user) {
    return res.status(401).json({ error: "invalid email or password" });
  }

  const passwordMatches = await bcrypt.compare(password, user.passwordHash);

  if (!passwordMatches) {
    return res.status(401).json({ error: "invalid email or password" });
  }

  // Instead of creating a session, we SIGN a token containing the claims
  // we want to trust later. Nothing is stored server-side - the token
  // itself is the proof of identity from now on.
  const token = jwt.sign(
    { userId: user.id, email: user.email }, // payload - readable by anyone, not secret
    JWT_SECRET,
    { expiresIn: "15m" }, // short-lived on purpose - we'll deal with renewing this via refresh tokens next
  );

  res.json({ token });
});

// --- Middleware: verify the JWT on protected routes ---
function requireAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  // Convention: the client sends "Authorization: Bearer <token>"
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "no token provided" });
  }

  try {
    // This recomputes the signature from the header+payload using JWT_SECRET
    // and compares it to the signature embedded in the token - exactly the
    // process we just discussed. Throws if invalid or expired.
    const decoded = jwt.verify(token, JWT_SECRET) as {
      userId: number;
      email: string;
    };
    req.user = { userId: decoded.userId, email: decoded.email };
    next();
  } catch (err) {
    return res.status(401).json({ error: "invalid or expired token" });
  }
}

// --- Protected route ---
app.get("/profile", requireAuth, (req, res) => {
  res.json({
    message: `This is your profile, user #${req.user!.userId} (${req.user!.email})`,
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
