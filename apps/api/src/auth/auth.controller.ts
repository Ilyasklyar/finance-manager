import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  Get,
  UnauthorizedException,
  UseGuards,
  NotFoundException,
} from '@nestjs/common';

import type { Request, Response } from 'express';

import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { AuthGuard } from './auth.guard';
import { UsersService } from '../users/users.service';

type AuthRequest = Request & {
  cookies: {
    refresh_token?: string;
    access_token?: string;
  };
};

type AuthenticatedRequest = AuthRequest & {
  user: {
    sub: string;
  };
};

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
  ) {}

  @Post('register')
  register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.login(loginDto, response);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refresh(
    @Req() request: AuthRequest,
    @Res({ passthrough: true }) response: Response,
  ) {
    const refreshToken = request.cookies.refresh_token;

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token is missing');
    }

    return this.authService.refreshTokens(refreshToken, response);
  }

  @Get('me')
  @UseGuards(AuthGuard)
  async me(@Req() request: AuthenticatedRequest) {
    const userId = request.user.sub;

    const user = await this.usersService.findById(userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(
    @Req() request: AuthRequest,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.logout(request.cookies?.refresh_token, response);
  }
}
