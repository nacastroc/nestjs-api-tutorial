import { IsEmail, IsInt, IsNotEmpty, IsNumber } from 'class-validator';

export class TokenPayloadDto {
  @IsInt()
  @IsNotEmpty()
  sub: number;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsNumber()
  @IsNotEmpty()
  exp: number;

  @IsNumber()
  @IsNotEmpty()
  iat: number;
}
