import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { ConfigService } from '@nestjs/config';

type AuthRequest = Request & {
  cookies: {
    access_token?: string;
  };
  user?: {
    sub: string;
  };
};

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthRequest>();
    const token = request.cookies?.access_token;

    if (!token) {
      throw new UnauthorizedException();
    }

    const secret = this.configService.getOrThrow<string>('JWT_ACCESS_SECRET');

    try {
      const payload = await this.jwtService.verifyAsync<{ sub: string }>(
        token,
        { secret },
      );

      if (typeof payload.sub !== 'string' || !payload.sub) {
        throw new UnauthorizedException();
      }

      request.user = { sub: payload.sub };
      return true;
    } catch {
      throw new UnauthorizedException();
    }
  }
}
