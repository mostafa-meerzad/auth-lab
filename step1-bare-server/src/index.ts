import express from "express";

const app = express();

// This lets Express automatically parse incoming JSON request bodies
// into req.body. Without this, req.body would be undefined.
app.use(express.json());

// A public route - anyone can hit this, no identity involved at all.
// This is our baseline: "no auth" behavior, so later we can clearly
// see what auth *adds* on top of this.
app.get("/", (req, res) => {
  res.send("Hello, no auth yet.");
});

// A route that PRETENDS to be sensitive, e.g. "get my profile".
// Right now it has no protection - anyone can call it and it just
// returns fake data. This is the gap we're about to close.
app.get("/profile", (req, res) => {
  res.json({
    message: "This should require login eventually, but doesn't yet.",
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
