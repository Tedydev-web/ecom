import { Inject, Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { IRedisService } from '../providers/redis/redis.interface'
import { RedisKeyManager } from '../providers/redis/redis-key.manager'
import * as tokens from 'src/shared/constants/injection.tokens'

@Injectable()
export class SessionService {
  constructor(
    @Inject(tokens.REDIS_SERVICE) private readonly redis: IRedisService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Marks a refresh token JTI as used to prevent replay attacks.
   * This is the core of Refresh Token Rotation.
   * @param jti The JTI of the refresh token.
   * @returns Promise<void>
   */
  async markRefreshTokenAsUsed(jti: string): Promise<void> {
    const key = RedisKeyManager.getUsedRefreshTokenKey(jti)
    const ttl = this.configService.get<number>('jwt.refreshToken.expiresInMs')! / 1000
    await this.redis.set(key, '1', ttl)
  }

  /**
   * Checks if a refresh token has already been used.
   * @param jti The JTI of the refresh token.
   * @returns True if the token has been used, false otherwise.
   */
  async isRefreshTokenUsed(jti: string): Promise<boolean> {
    const key = RedisKeyManager.getUsedRefreshTokenKey(jti)
    const result = await this.redis.get(key)
    return result === '1'
  }

  /**
   * Adds a token's JTI to the blacklist.
   * @param jti The JTI of the token to blacklist.
   * @param ttlSeconds The remaining time-to-live for the token.
   */
  async addToBlacklist(jti: string, ttlSeconds: number): Promise<void> {
    if (ttlSeconds > 0) {
      const key = RedisKeyManager.getBlacklistedTokenKey(jti)
      await this.redis.set(key, '1', Math.ceil(ttlSeconds))
    }
  }

  /**
   * Checks if a token's JTI is in the blacklist.
   * @param jti The JTI of the token.
   * @returns True if the token is blacklisted, false otherwise.
   */
  async isBlacklisted(jti: string): Promise<boolean> {
    const key = RedisKeyManager.getBlacklistedTokenKey(jti)
    const result = await this.redis.get(key)
    return result === '1'
  }
}
