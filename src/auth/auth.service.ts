import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private _prismaService: PrismaService,
    private _jwtService: JwtService,
    private _configService: ConfigService,
  ) {}

  async signUp(dto: AuthDto) {
    try {
      // Generate the hash for the password.
      const hash = await argon.hash(dto.password);
      // Save the new user to the DB.
      const user = await this._prismaService.user.create({
        data: {
          email: dto.email,
          hash: hash,
        },
      });
      // Return the user jwt token.
      const access_token = await this.signToken(user.id, user.email);
      return { access_token };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }

  async signIn(dto: AuthDto) {
    try {
      // Find the user by email.
      // If user does not exists, throw exception.
      const user = await this._prismaService.user.findFirstOrThrow({
        where: { email: dto.email },
      });
      // Compare passwords.
      const pwdMatches = await argon.verify(user.hash, dto.password);
      // If password is incorrect, throw exception.
      if (!pwdMatches) throw new ForbiddenException('Incorrect credentials');
      // Return the user jwt token.
      const access_token = await this.signToken(user.id, user.email);
      return { access_token };
    } catch (error) {
      // Throw forbidden exception if user not found.
      if (error.code === 'P2025') {
        throw new ForbiddenException('Incorrect credentials');
      }
      throw error;
    }
  }

  private async signToken(userId: number, email: string) {
    const payload = {
      sub: userId,
      email: email,
    };
    const secret = this._configService.get('JWT_SECRET');
    return this._jwtService.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });
  }
}
