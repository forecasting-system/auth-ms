import * as bcrypt from 'bcrypt';
import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { RpcException } from '@nestjs/microservices';

import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';
import { LoginUserDto, RegisterUserDto } from 'src/dto';
import { PrismaClient } from 'generated/prisma';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  async onModuleInit() {
    await this.$connect();
    this.logger.log('Database connected');
  }

  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return { user, token: await this.signJWT(user) };
    } catch (error) {
      throw new RpcException({
        message: 'Invalid token',
        status: HttpStatus.UNAUTHORIZED,
      });
    }
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, name, password } = registerUserDto;

    try {
      const user = await this.user.findUnique({
        where: {
          email,
        },
      });

      if (user) {
        throw new RpcException({
          message: 'User already exists',
          status: HttpStatus.BAD_REQUEST,
        });
      }

      const newUser = await this.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, 10),
          name,
        },
      });

      const { password: __, ...rest } = newUser;

      return {
        user: rest,
        token: await this.signJWT(rest),
      };
    } catch (err) {
      throw new RpcException({
        message: err.message,
        status: HttpStatus.BAD_REQUEST,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    try {
      const user = await this.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new RpcException({
          message: 'Invalid credentials',
          status: HttpStatus.BAD_REQUEST,
        });
      }

      const isPasswordValid = bcrypt.compareSync(password, user.password);

      if (!isPasswordValid) {
        throw new RpcException({
          message: 'Invalid credentials',
          status: HttpStatus.BAD_REQUEST,
        });
      }

      const { password: __, ...rest } = user;

      return {
        user: rest,
        token: await this.signJWT(rest),
      };
    } catch (err) {
      throw new RpcException({
        message: err.message,
        status: HttpStatus.BAD_REQUEST,
      });
    }
  }
}
