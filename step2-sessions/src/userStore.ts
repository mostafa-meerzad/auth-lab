// A fake "database" - just an array in memory. In a real app this would
// be a Postgres/Mongo table, but keeping it in-memory lets us focus
// purely on the auth logic without DB setup noise.

export interface User {
  id: number;
  email: string;
  passwordHash: string; // NEVER store the raw password - only the bcrypt hash
}

export const users: User[] = [];

let nextId = 1;

export function createUser(email: string, passwordHash: string): User {
  const user: User = { id: nextId++, email, passwordHash };
  users.push(user);
  return user;
}

export function findUserByEmail(email: string): User | undefined {
  return users.find((u) => u.email === email);
}