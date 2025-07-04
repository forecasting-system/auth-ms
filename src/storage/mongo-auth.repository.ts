import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { AuthRepository } from './interface/auth.repository.interface';
import { PrismaClient } from 'generated/prisma';
import { NewUser, User } from 'src/model/user';

@Injectable()
export class MongoAuthRepository
  extends PrismaClient
  implements AuthRepository, OnModuleInit
{
  private readonly logger = new Logger('Mongo Auth Repository');

  onModuleInit() {
    this.$connect();
    this.logger.log('Database connected');
  }

  async findUser(email: string): Promise<User | null> {
    const userData = await this.user.findUnique({
      where: {
        email,
      },
    });

    if (!userData) {
      return null;
    }

    const user = new User(
      userData.id,
      userData.email,
      userData.name,
      userData.password,
    );

    return user;
  }

  async createUser(user: NewUser): Promise<User> {
    const newUserData = await this.user.create({
      data: {
        email: user.email,
        password: user.password,
        name: user.name,
      },
    });

    const newUser = new User(
      newUserData.id,
      newUserData.email,
      newUserData.name,
      newUserData.password,
    );

    return newUser;
  }
}
