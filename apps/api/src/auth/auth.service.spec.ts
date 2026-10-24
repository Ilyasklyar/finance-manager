import { ConflictException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { Prisma } from 'generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { AuthService } from './auth.service';

jest.mock('bcryptjs', () => ({
  hash: jest.fn(),
}));

describe('AuthService', () => {
  let service: AuthService;
  let prisma: {
    user: { create: jest.Mock };
  };

  beforeEach(() => {
    prisma = {
      user: { create: jest.fn() },
    };

    service = new AuthService(
      prisma as unknown as PrismaService,
      {} as JwtService,
      {} as ConfigService,
    );

    jest.mocked(bcrypt.hash).mockResolvedValue('hashed-password' as never);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('register', () => {
    const registerDto = {
      name: 'Ada Lovelace',
      email: 'ada@example.com',
      password: 'correct-horse-battery',
    };

    it('hashes the password and returns the selected user fields', async () => {
      const createdUser = {
        id: 'user-1',
        name: registerDto.name,
        email: registerDto.email,
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        updatedAt: new Date('2026-01-01T00:00:00.000Z'),
      };
      jest.mocked(bcrypt.hash).mockResolvedValue('hashed-password' as never);
      prisma.user.create.mockResolvedValue(createdUser);

      await expect(service.register(registerDto)).resolves.toEqual(createdUser);

      expect(bcrypt.hash).toHaveBeenCalledWith(registerDto.password, 10);
      expect(prisma.user.create).toHaveBeenCalledWith({
        data: {
          name: registerDto.name,
          email: registerDto.email,
          passwordHash: 'hashed-password',
        },
        select: {
          id: true,
          name: true,
          email: true,
          createdAt: true,
          updatedAt: true,
        },
      });
    });

    it('converts a Prisma duplicate email error to a conflict exception', async () => {
      const duplicateEmailError = new Prisma.PrismaClientKnownRequestError(
        'Unique constraint failed',
        { code: 'P2002', clientVersion: 'test' },
      );
      prisma.user.create.mockRejectedValue(duplicateEmailError);
      const registration = service.register(registerDto);

      await expect(registration).rejects.toBeInstanceOf(ConflictException);
      await expect(registration).rejects.toThrow('Email already exists');
    });
  });
});
