import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private _authService: AuthService) {}

  @Post('signup')
  signUp(@Body() dto: AuthDto) {
    return this._authService.signUp(dto);
  }

  @HttpCode(HttpStatus.OK) // Returns 200 instead of 201.
  @Post('signin')
  signIn(@Body() dto: AuthDto) {
    return this._authService.signIn(dto);
  }
}
