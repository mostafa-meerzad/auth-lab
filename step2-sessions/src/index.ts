import express from "express";
import bcrypt from "bcrypt";
import session from "express-session";
import { createUser, findUserByEmail } from "./userStore";

const app = express();
app.use(express.json());

// --- Session middleware setup ---
// This is what makes req.session exist on every request.
// Internally: on first response, it generates a session ID, stores session
// data server-side (in memory, by default - fine for learning, NOT for
// production, which would use Redis/DB), and sends the ID to the browser
// as a cookie. On future requests, it reads that cookie, looks up the
// matching session, and attaches it as req.session.
app.use(
  session({
    secret: "learning-secret-do-not-use-in-prod", // signs the session ID cookie so it can't be tampered with
    resave: false,            // don't re-save session if nothing changed
    saveUninitialized: false, // don't create a session until something is stored in it
    cookie: {
      httpOnly: true, // JS on the frontend can't read this cookie - blocks a whole class of XSS token theft
      secure: false,  // would be true in production (HTTPS only) - false here since we're on plain localhost
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

// --- Register ---
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }

  if (findUserByEmail(email)) {
    return res.status(409).json({ error: "user already exists" });
  }

  // bcrypt.hash does the salting AND hashing in one call.
  // The "10" is the cost factor - higher = slower = harder to brute-force,
  // but also slower for real logins. 10 is a reasonable default.
  const passwordHash = await bcrypt.hash(password, 10);

  const user = createUser(email, passwordHash);

  res.status(201).json({ id: user.id, email: user.email });
});

// --- Login ---
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = findUserByEmail(email);
  if (!user) {
    // Deliberately vague error - we don't want to reveal whether the
    // email exists or the password was wrong. That distinction helps attackers.
    return res.status(401).json({ error: "invalid email or password" });
  }

  // bcrypt.compare re-hashes the incoming password (using the salt embedded
  // in the stored hash) and checks if it matches. We never decrypt anything.
  const passwordMatches = await bcrypt.compare(password, user.passwordHash);
  if (!passwordMatches) {
    return res.status(401).json({ error: "invalid email or password" });
  }

  // THIS is the moment authentication succeeds and we start a session.
  // We only store the user's ID in the session - never the password,
  // never the whole user object.
  req.session.userId = user.id;

  res.json({ message: `Logged in as ${user.email}` });
});

// --- Logout ---
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "Logged out" });
  });
});

// --- A middleware that protects routes ---
// This is authentication ENFORCEMENT: it runs before the route handler
// and blocks the request if there's no valid session.
function requireAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "not logged in" });
  }
  next(); // identity confirmed, let the request continue to the actual route
}

// --- Protected route ---
app.get("/profile", requireAuth, (req, res) => {
  res.json({ message: `This is your profile, user #${req.session.userId}` });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});