import { Global, Module } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { HashingService } from './services/hashing.service'
import { TokenService } from './services/token.service'
import { JwtModule } from '@nestjs/jwt'
import { AccessTokenGuard } from 'src/shared/guards/access-token.guard'
import { APIKeyGuard } from 'src/shared/guards/api-key.guard'
import { APP_GUARD } from '@nestjs/core'
import { AuthenticationGuard } from 'src/shared/guards/authentication.guard'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { EmailService } from 'src/shared/services/email.service'
import { TwoFactorService } from 'src/shared/services/2fa.service'
import { CookieService } from './services/cookie.service'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { RedisService } from './providers/redis/redis.service'
import { IORedisKey } from './providers/redis/redis.constants'
import Redis from 'ioredis'
import { Logger } from '@nestjs/common'
import { CryptoService } from './services/crypto.service'
import { SessionService } from './services/session.service'
import { UserAgentService } from './services/user-agent.service'
import * as tokens from './constants/injection.tokens'
import { SecurityHeadersMiddleware } from './middleware/security-headers.middleware'
import { CsrfProtectionMiddleware } from './middleware/csrf.middleware'

const redisClientProvider = {
  provide: IORedisKey,
  useFactory: (configService: ConfigService) => {
    const logger = new Logger('RedisProviderFactory')
    const client = new Redis({
      host: configService.get<string>('redis.host'),
      port: configService.get<number>('redis.port'),
      password: configService.get<string>('redis.password'),
      db: configService.get<number>('redis.db'),
      retryStrategy: (times: number) => {
        const delay = Math.min(times * 100, 3000) // Tối đa 3s
        logger.warn(`Redis: Đang thử kết nối lại (lần ${times}), thử lại sau ${delay}ms.`)
        return delay
      },
    })

    client.on('error', (err) => {
      logger.error('Redis Client Error:', err)
    })

    return client
  },
  inject: [ConfigService],
}

// Danh sách các class service để NestJS có thể khởi tạo chúng
const serviceClasses = [
  PrismaService,
  HashingService,
  TokenService,
  EmailService,
  SharedUserRepository,
  TwoFactorService,
  CookieService,
  CryptoService,
  SessionService,
  UserAgentService,
  RedisService,
]

// Thêm middleware vào danh sách các class để NestJS quản lý
const middlewareClasses = [CsrfProtectionMiddleware, SecurityHeadersMiddleware]

// Danh sách các providers sử dụng token, tuân thủ nguyên tắc Dependency Inversion
const tokenProviders = [
  { provide: tokens.PRISMA_SERVICE, useClass: PrismaService },
  { provide: tokens.HASHING_SERVICE, useClass: HashingService },
  { provide: tokens.TOKEN_SERVICE, useClass: TokenService },
  { provide: tokens.EMAIL_SERVICE, useClass: EmailService },
  { provide: tokens.SHARED_USER_REPOSITORY, useClass: SharedUserRepository },
  { provide: tokens.TWO_FACTOR_SERVICE, useClass: TwoFactorService },
  { provide: tokens.COOKIE_SERVICE, useClass: CookieService },
  { provide: tokens.CRYPTO_SERVICE, useClass: CryptoService },
  { provide: tokens.SESSION_SERVICE, useClass: SessionService },
  { provide: tokens.USER_AGENT_SERVICE, useClass: UserAgentService },
  { provide: tokens.REDIS_SERVICE, useClass: RedisService },
]

const guardClasses = [AccessTokenGuard, APIKeyGuard, AuthenticationGuard]

const allProviders = [
  ...serviceClasses,
  ...middlewareClasses,
  ...tokenProviders,
  ...guardClasses,
  redisClientProvider,
  {
    provide: APP_GUARD,
    useClass: AuthenticationGuard,
  },
  { provide: tokens.ACCESS_TOKEN_GUARD, useClass: AccessTokenGuard },
  { provide: tokens.API_KEY_GUARD, useClass: APIKeyGuard },
]

@Global()
@Module({
  imports: [JwtModule, ConfigModule],
  providers: allProviders,
  exports: [
    ...serviceClasses,
    ...middlewareClasses,
    ...tokenProviders,
    ...guardClasses,
    tokens.ACCESS_TOKEN_GUARD,
    tokens.API_KEY_GUARD,
    tokens.PRISMA_SERVICE,
  ],
})
export class SharedModule {}
