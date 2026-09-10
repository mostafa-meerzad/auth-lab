# Authentication & Authorization explained

## Concept 1: Authentication vs Authorization

**Authentication (AuthN)** answers: _"Who are you?"_
It's the process of verifying identity — you give credentials (email/password, a token, a fingerprint, whatever), and the system confirms you are who you claim to be. The output of authentication is: "OK, you're user #42."

**Authorization (AuthZ)** answers: _"What are you allowed to do?"_
It happens _after_ authentication. Once the system knows you're user #42, authorization decides whether user #42 can delete this post, view that admin page, or hit that API route.

The reason people mix these up: they often happen back-to-back and both can "fail" with what looks like the same result (a rejected request). But they're fundamentally different checks:

|                    | Authentication                                | Authorization                                 |
| ------------------ | --------------------------------------------- | --------------------------------------------- |
| Question           | Who are you?                                  | What can you do?                              |
| When               | First, at login/each request                  | After identity is known                       |
| Failure looks like | 401 Unauthorized ("I don't know who you are") | 403 Forbidden ("I know who you are, but no")  |
| Example            | Logging in with email+password                | An "editor" role can't access the admin panel |

A concrete mental model: authentication is the **bouncer checking your ID at the door**. Authorization is **the wristband system inside** — VIP wristband gets you backstage, general admission doesn't, regardless of whether the bouncer already confirmed you're a real person.

This distinction matters practically because **they live in different places in your code**. Authentication usually happens once (login) and produces something (a session or token) that proves identity on later requests. Authorization is checked _per action_, every time, based on what that identity is permitted to do — and this is where RBAC comes in, which we'll get to once we've built basic authentication first.

One more piece of vocabulary before we code: whatever "proof of identity" gets handed back after login (a cookie referencing a session, or a JWT) is what every subsequent request will carry so the server doesn't have to ask you to log in again on every single click. That "how do we remember who you are across requests" problem is exactly what Phase 1, step 1-2 will tackle.

---

Quick gut-check before we start scaffolding the Express project — does the AuthN/AuthZ split make sense so far, or want me to hit it from another angle (e.g. a bad real-world bug example where the two get confused)? Once you're good, I'll set up the bare Express+TS server (Phase 1, step 1) and we start writing actual code.

---

Great — let's build.

## Phase 1, Step 1: Bare Express server (no auth yet)

Before adding any auth, we need the skeleton. This step is just to get you comfortable with the request/response cycle we'll be layering auth onto — nothing conceptually new here if you've used Express before, but I'll narrate it anyway so nothing is assumed.Both routes work as expected. Here's what's actually going on, piece by piece:

- **`app.use(express.json())`** — a middleware. Every request passes through it before hitting your route handlers; this one parses JSON bodies. Middleware is the exact mechanism we'll use for auth checks later (a middleware that runs _before_ a route and can reject the request before it ever reaches your handler).
- **`/`** — completely public, no identity concept exists yet.
- **`/profile`** — this is deliberately fake-sensitive. It _should_ require someone to be logged in, but right now it just answers anyone. This is our "before" picture — in the next step we make this route actually check identity.

**Where we are in the roadmap:** Phase 1, Step 1 done ✅. Next is **Step 2: manual session-based auth** — you'll register a user (password gets hashed, never stored raw), log in, and the server will start tracking "this browser is user X" via a session + cookie. That's where authentication actually begins.

Ready to move to Step 2, or do you want to poke at this bare server first (e.g. see what happens with a bad route, or add a second dummy endpoint) before we add auth on top of it?

---

Got it — theory fully first, then we build that step's piece of the server. Let's go.

## Concept 2: Password Storage & Sessions

**Never store passwords in plaintext — and never store them "encrypted" either.** Encryption is reversible (there's a key that decrypts it), which means if your database or that key ever leaks, every password leaks in plain form. Instead we **hash** passwords. A hash is a one-way function: easy to compute forward (`password` → `a1b2c3...`), practically impossible to reverse. To check a login, you don't decrypt anything — you hash the _incoming_ password and compare it to the stored hash.

Why not just use something fast like SHA-256 for this? Because speed is the enemy here. If an attacker steals your database of hashes, they'll try to crack them by hashing millions of guesses per second and comparing. A generic fast hash lets them try billions of guesses/sec on modern hardware. Password-specific algorithms like **bcrypt** or **argon2** are deliberately slow and tunable ("cost factor") — you can make them slow enough that guessing becomes impractical, while a legitimate login (one hash operation) is still fast enough not to bother a real user. We'll use **bcrypt** since it's the most common and battle-tested.

One more ingredient: **salting**. A salt is random data mixed into the password before hashing, unique per user. Without it, two users with the same password would produce the identical hash — and worse, attackers can precompute hash tables for common passwords ("rainbow tables") and instantly crack any match. bcrypt handles salting for you automatically and stores the salt as part of the output hash string, so you don't manage it separately.

**Now, sessions.** HTTP itself is stateless — the server doesn't inherently remember you between requests. So after a successful login, the server needs a way to recognize "this next request is from the same person who just logged in." The classic approach:

1. Server creates a **session** — a record (in memory, or a DB/Redis) saying "session ID `xyz` belongs to user #42"
2. Server sends the browser a **cookie** containing that session ID
3. Browser automatically attaches that cookie on every future request to the same domain
4. Server looks up the session ID from the cookie, finds "oh, that's user #42," and now every route knows who's asking

This is authentication working end-to-end for the first time: the login endpoint verifies identity (bcrypt compare), and the session+cookie mechanism carries that proven identity across future requests without re-checking the password every time.

We'll build it in this order: register (hash + store) → login (verify + create session) → a protected route that checks for a valid session.

Make sense to move into code for this piece now?

---

Now let's actually run it and walk through the full flow with real requests — register, login, hit the protected route, then try it without a session.That's the whole authentication loop working end-to-end. Let's map what just happened back to the requests:

1. **Register** → password never touched the response or gets logged anywhere raw — bcrypt hashed it before it ever hit `users[]`.
2. **Login** → bcrypt compared the given password against the stored hash, matched, and `req.session.userId = user.id` fired. Behind the scenes, `curl -c cookies.txt` saved the `Set-Cookie` header the server sent back — that's the session ID.
3. **Profile with cookie** → the cookie came back on the request, `express-session` looked up the session, found `userId: 1`, `requireAuth` let it through.
4. **Profile without cookie** → no session found → `requireAuth` blocked it with a 401, before the route handler even ran.

That 401 in step 4 is the concrete proof that **authorization-style enforcement (the middleware) is separate from the route logic itself** — the route handler never even executes for an unauthenticated request.**Where we are:** Phase 1, Step 2 done ✅ — session-based auth with hashed passwords, working register/login/logout/protected-route flow.Next up is **Step 3: JWT-based auth** — same login flow, but instead of a server-side session, the server hands back a signed token that _contains_ the identity, so nothing needs to be stored server-side to verify it. Want the theory for that now, or anything you want to poke at on this session-based version first (e.g. what happens if you tamper with the cookie, or inspect what the session actually looks like server-side)?

---

## Concept 3: JWT-based Authentication

We just built session-based auth, where the server keeps state (a session record) and the browser only holds a reference (session ID) to it. JWT flips this: the token itself _contains_ the identity information, cryptographically signed, so the server doesn't need to store anything to verify it. This is called **stateless auth**.

**Structure of a JWT.** A JWT is three base64-encoded parts joined by dots: `header.payload.signature`.

- **Header** — metadata, mainly which signing algorithm was used (e.g. HS256)
- **Payload** — the actual claims, e.g. `{ userId: 1, email: "...", iat: ..., exp: ... }`. This is just base64-_encoded_, not encrypted — anyone can decode and read it (try it on jwt.io). **Never put secrets/passwords in the payload.**
- **Signature** — the header + payload, signed with a secret key the server holds. This is what makes the token trustworthy: if anyone modifies the payload (e.g. changes `userId: 1` to `userId: 2`), the signature won't match anymore when the server checks it, and the token gets rejected.

**Signing vs encryption — an important distinction.** A JWT is _signed_, not _encrypted_. Signing proves the content wasn't tampered with and came from someone holding the secret — it does **not** hide the content. Anyone who intercepts the token can read the payload. Encryption (a different, less common JWT variant, JWE) would hide the content too, but standard JWT auth (JWS) is just tamper-proof, not confidential. This is exactly why we said in Concept 1 not to put sensitive data in there.

**How the flow changes from sessions:**

1. Login: verify credentials (same bcrypt check as before) — but instead of creating a server-side session, the server just **signs a token** containing the user's identity and hands it back in the response body (not automatically as a cookie this time — more on storage location later, in the React step).
2. Client stores that token and attaches it on future requests, typically in an `Authorization: Bearer <token>` header.
3. Server verifies incoming requests by simply checking the token's signature and expiry — no database or session-store lookup needed at all. If the signature is valid and it's not expired, the server trusts the claims inside it.

**Why this matters architecturally:** sessions require the server to be stateful — every server instance needs to reach the same shared session store, which becomes a real coordination problem once you have multiple server instances (load balancing, microservices). JWTs let _any_ server instance validate a request completely independently, since all the info needed is in the token itself, verified with a secret every instance shares. This is the main reason APIs and microservice architectures lean toward JWT.

**The tradeoff — you can't "log out" a JWT.** With sessions, logout = delete the session record server-side, done. With JWTs, the server never stored anything, so there's nothing to delete — the token remains valid (signature still checks out) until it naturally expires. This is the single biggest practical downside of JWTs and it's exactly why real systems use **short-lived access tokens** (minutes) plus a **separate refresh token** mechanism — which is Concept 4, right after this, and directly addresses this exact problem.

That's the core of it. Want me to go a bit deeper into any part before we code Step 3 (e.g. exactly how `jsonwebtoken`'s `sign`/`verify` works under the hood, or a worked example of tampering with a token and watching verification fail), or are we good to move into code?

---

Exactly right — that's precisely what happens.

When `jwt.verify()` runs, it:

1. Splits the incoming token back into its three parts: header, payload, signature
2. Takes the header + payload (still base64-encoded, exactly as received) and re-runs the same signing algorithm on them using the server's secret — producing a fresh signature
3. Compares that freshly-computed signature to the signature that arrived in the token

If they match byte-for-byte, the token is considered untampered and genuinely issued by someone holding the secret (presumably your own server, from a prior login). If even one character of the header or payload was changed after signing, the recomputed signature won't match, and verification fails outright — the server never even gets to the point of "trusting" the payload's claims. This is also why `verify()` naturally checks `exp` (expiry) as part of the same call — no separate storage lookup needed anywhere in this process, which is the stateless property we talked about.

Now let's build it.Now let's run the full flow, including deliberately tampering with the token to prove the signature check actually works.Good, the edit did take. Let me kill any stale process and restart cleanly with separate steps to avoid a timing race.No lingering processes. Let's start fresh.Server's up. Now the full walkthrough:That's the issue — background processes don't survive between separate tool calls; I need to start the server and run the test in the same call, like before.All three cases behave exactly as expected:

- **Valid token** → decoded, signature checked out, request went through
- **No token** → rejected before any verification even happens (`no token provided`)
- **Tampered token** (I appended a stray `x` to the signature) → `jwt.verify()` recomputed the signature from the header+payload, it didn't match the (now-corrupted) signature in the token, and it threw — caught in our `catch` block as `invalid or expired token`

That tampered-token test is the concrete proof of the exact mechanism we talked about earlier: the server re-derives the signature and compares, and any modification — even one character — breaks it.

You can also decode the token payload yourself anytime at [jwt.io](https://jwt.io) — paste that token in and you'll see the `userId`, `email`, `iat`, `exp` sitting there in plain readable JSON, which drives home the "signed, not encrypted" point.Ready for **Concept 4: refresh tokens** — the fix for "you can't log out a JWT" — whenever you are.
