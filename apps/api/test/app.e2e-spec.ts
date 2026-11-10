import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import cookieParser from 'cookie-parser';
import { App } from 'supertest/types';
import { AppModule } from './../src/app.module';
import { PrismaService } from './../src/prisma/prisma.service';
import { UsersService } from './../src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';

const usersServiceMock = {
  findById: jest.fn(),
};

type FindMany = PrismaService['refreshSession']['findMany'];
type UpdateMany = PrismaService['refreshSession']['updateMany'];

const prismaMock = {
  refreshSession: {
    findMany: jest.fn() as jest.MockedFunction<FindMany>,
    updateMany: jest.fn() as jest.MockedFunction<UpdateMany>,
  },
};

const testUser = {
  id: 'user-1',
  email: 'test@example.com',
  name: 'Test User',
  createdAt: new Date('2026-01-01T00:00:00.000Z'),
  updatedAt: new Date('2026-01-01T00:00:00.000Z'),
};

describe('AuthController (e2e)', () => {
  let app: INestApplication<App>;
  let jwtService: JwtService;
  let configService: ConfigService;

  beforeEach(() => {
    usersServiceMock.findById.mockReset();
    prismaMock.refreshSession.findMany.mockReset();
    prismaMock.refreshSession.updateMany.mockReset();
  });

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(PrismaService)
      .useValue(prismaMock)
      .overrideProvider(UsersService)
      .useValue(usersServiceMock)
      .compile();

    app = moduleFixture.createNestApplication();
    app.use(cookieParser());

    await app.init();
    jwtService = app.get(JwtService);
    configService = app.get(ConfigService);
  });

  afterAll(async () => {
    await app.close();
  });

  async function createAccessToken(userId: string) {
    return jwtService.signAsync(
      { sub: userId },
      {
        secret: configService.getOrThrow<string>('JWT_ACCESS_SECRET'),
        expiresIn: '15m',
      },
    );
  }

  it('POST /auth/refresh — returns 401 when refresh cookie is missing', async () => {
    await request(app.getHttpServer()).post('/auth/refresh').expect(401);
  });

  it('GET /auth/me — returns 401 when access cookie is missing', async () => {
    await request(app.getHttpServer()).get('/auth/me').expect(401);

    expect(usersServiceMock.findById).not.toHaveBeenCalled();
  });

  it('GET /auth/me — returns 401 when access token is invalid', async () => {
    await request(app.getHttpServer())
      .get('/auth/me')
      .set('Cookie', ['access_token=invalid-token'])
      .expect(401);

    expect(usersServiceMock.findById).not.toHaveBeenCalled();
  });

  it('GET /auth/me — returns 200 and current user when access token is valid', async () => {
    usersServiceMock.findById.mockResolvedValue(testUser);

    const accessToken = await createAccessToken(testUser.id);

    await request(app.getHttpServer())
      .get('/auth/me')
      .set('Cookie', [`access_token=${accessToken}`])
      .expect(200)
      .expect({
        ...testUser,
        createdAt: testUser.createdAt.toISOString(),
        updatedAt: testUser.updatedAt.toISOString(),
      });

    expect(usersServiceMock.findById).toHaveBeenCalledTimes(1);
    expect(usersServiceMock.findById).toHaveBeenCalledWith(testUser.id);
  });

  it('GET /auth/me — returns 404 when user is not found', async () => {
    usersServiceMock.findById.mockResolvedValue(null);

    const accessToken = await createAccessToken('user-123');

    await request(app.getHttpServer())
      .get('/auth/me')
      .set('Cookie', [`access_token=${accessToken}`])
      .expect(404);

    expect(usersServiceMock.findById).toHaveBeenCalledWith('user-123');
  });

  it('GET /auth/me — returns 401 when access token is expired', async () => {
    const expiredToken = await jwtService.signAsync(
      { sub: testUser.id },
      {
        secret: configService.getOrThrow<string>('JWT_ACCESS_SECRET'),
        expiresIn: '-1s',
      },
    );

    await request(app.getHttpServer())
      .get('/auth/me')
      .set('Cookie', [`access_token=${expiredToken}`])
      .expect(401);

    expect(usersServiceMock.findById).not.toHaveBeenCalled();
  });

  it('POST /auth/logout — clears cookies when refresh cookie is missing', async () => {
    const response = await request(app.getHttpServer())
      .post('/auth/logout')
      .expect(200);

    expect(response.body).toEqual({
      message: 'Logged out successfully',
    });

    expect(response.headers['set-cookie']).toEqual(
      expect.arrayContaining([
        expect.stringContaining('access_token=;'),
        expect.stringContaining('refresh_token=;'),
      ]),
    );

    expect(prismaMock.refreshSession.findMany).not.toHaveBeenCalled();
    expect(prismaMock.refreshSession.updateMany).not.toHaveBeenCalled();
  });

  it('POST /auth/logout — returns 200 and revokes refresh session when refresh token is valid', async () => {
    const refreshToken = await jwtService.signAsync(
      { sub: testUser.id },
      {
        secret: configService.getOrThrow<string>('JWT_REFRESH_SECRET'),
        expiresIn: '7d',
      },
    );

    const tokenHash = await bcrypt.hash(refreshToken, 10);

    prismaMock.refreshSession.findMany.mockResolvedValue([
      {
        id: 'session-1',
        userId: testUser.id,
        tokenHash,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        createdAt: new Date(),
        revokedAt: null,
      },
    ]);

    prismaMock.refreshSession.updateMany.mockResolvedValue({
      count: 1,
    });

    const response = await request(app.getHttpServer())
      .post('/auth/logout')
      .set('Cookie', [`refresh_token=${refreshToken}`])
      .expect(200);

    expect(response.body).toEqual({
      message: 'Logged out successfully',
    });

    expect(response.headers['set-cookie']).toEqual(
      expect.arrayContaining([
        expect.stringContaining('access_token=;'),
        expect.stringContaining('refresh_token=;'),
      ]),
    );

    // Verify that active sessions were searched for the authenticated user.
    expect(prismaMock.refreshSession.findMany).toHaveBeenCalledTimes(1);

    const findManyCall = prismaMock.refreshSession.findMany.mock.calls[0];

    if (!findManyCall?.[0]) {
      throw new Error('Expected findMany to be called with arguments');
    }

    const findManyArgs = findManyCall[0];

    expect(findManyArgs.where).toMatchObject({
      userId: testUser.id,
      revokedAt: null,
    });

    const expiresAt = findManyArgs.where?.expiresAt;

    if (
      typeof expiresAt !== 'object' ||
      expiresAt === null ||
      !('gt' in expiresAt)
    ) {
      throw new Error('Expected expiresAt to use a greater-than filter');
    }

    expect(expiresAt.gt).toBeInstanceOf(Date);

    // Verify that the matching refresh session was revoked.
    expect(prismaMock.refreshSession.updateMany).toHaveBeenCalledTimes(1);

    const updateCall = prismaMock.refreshSession.updateMany.mock.calls[0];

    if (!updateCall?.[0]) {
      throw new Error('Expected updateMany to be called with arguments');
    }

    const updateArgs = updateCall[0];

    expect(updateArgs.where).toEqual({
      id: 'session-1',
      revokedAt: null,
    });

    expect(updateArgs.data.revokedAt).toBeInstanceOf(Date);
  });
});
