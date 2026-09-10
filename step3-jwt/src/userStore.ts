export interface User {
  id: number;
  email: string;
  passwordHash: string;
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