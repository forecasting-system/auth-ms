import * as bcrypt from 'bcrypt';
import { HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { RpcException } from '@nestjs/microservices';

import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';
import { LoginUserDto, RegisterUserDto } from 'src/dto';

@Injectable()
export class AuthService {
  constructor(private readonly jwtService: JwtService) {
    // super();
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
      //   const user = await this.user.findUnique({
      //     where: {
      //       email,
      //     },
      //   });

      // TODO: temp code to be removed
      const user = null;

      if (user) {
        throw new RpcException({
          message: 'User already exists',
          status: HttpStatus.BAD_REQUEST,
        });
      }

      //   const newUser = await this.user.create({
      //     data: {
      //       email,
      //       password: bcrypt.hashSync(password, 10),
      //       name,
      //     },
      //   });

      //   const { password: __, ...rest } = newUser;

      // TODO: temp code to be removed
      const data = {
        id: '1',
        email,
        password: bcrypt.hashSync(password, 10),
        name,
      };

      const { password: __, ...rest } = data;

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
      //   const user = await this.user.findUnique({
      //     where: { email },
      //   });

      // TODO: temp code to be removed
      const user = {
        id: '1',
        email,
        password: bcrypt.hashSync(password, 10),
        name: 'John Doe',
      };

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
