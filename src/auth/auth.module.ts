import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { envs } from 'src/config';
import { AUTH_REPOSITORY } from 'src/storage/interface/auth.repository.interface';
import { MongoAuthRepository } from 'src/storage/mongo-auth.repository';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    { provide: AUTH_REPOSITORY, useClass: MongoAuthRepository },
  ],
  imports: [
    JwtModule.register({
      global: true,
      secret: envs.jwtSecret,
      signOptions: { expiresIn: '2h' },
    }),
  ],
})
export class AuthModule {}
