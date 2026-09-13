// Unlike access tokens, refresh tokens ARE tracked server-side. This is
// intentional - it's what gives us the ability to revoke them (logout,
// or detecting theft via rotation reuse), unlike stateless access tokens.
//
// Real apps store this in a database (a "refresh_tokens" table keyed by
// user, with expiry, device info, etc). In-memory here for learning.

interface StoredRefreshToken {
  token: string;
  userId: number;
}

const validRefreshTokens: StoredRefreshToken[] = [];

export function storeRefreshToken(token: string, userId: number) {
  validRefreshTokens.push({ token, userId });
}

export function isRefreshTokenValid(token: string): boolean {
  return validRefreshTokens.some((t) => t.token === token);
}

export function getUserIdForRefreshToken(token: string): number | undefined {
  return validRefreshTokens.find((t) => t.token === token)?.userId;
}

// Used during rotation: remove the old token so it can never be reused.
export function revokeRefreshToken(token: string) {
  const index = validRefreshTokens.findIndex((t) => t.token === token);
  if (index !== -1) validRefreshTokens.splice(index, 1);
}

// Used on logout "everywhere", or when reuse of an already-rotated token
// is detected (a strong signal of theft) - nukes every session for that user.
export function revokeAllRefreshTokensForUser(userId: number) {
  for (let i = validRefreshTokens.length - 1; i >= 0; i--) {
    if (validRefreshTokens[i].userId === userId) {
      validRefreshTokens.splice(i, 1);
    }
  }
}