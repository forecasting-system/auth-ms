import { IsEmail, IsString, IsStrongPassword } from 'class-validator';

export class RegisterUserDto {
  @IsString()
  name: string;

  @IsEmail()
  @IsString()
  email: string;

  @IsString()
  @IsStrongPassword()
  password: string;
}

export class RegisterUserOutDto {
  name: string;
  email: string;
  id: string;
}

export class AuthDataOutDto {
  user: RegisterUserOutDto;
  token: string;
}
