import { NewUser, User } from 'src/model/user';

export const AUTH_REPOSITORY = 'AuthRepository';

export interface AuthRepository {
  findUser(email: string): Promise<User | null>;
  createUser(user: NewUser): Promise<User>;
}
