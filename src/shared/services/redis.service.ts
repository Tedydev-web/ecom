import { Injectable, Inject, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common'
import Redis, { RedisKey, RedisValue } from 'ioredis'
import { IORedisKey } from '../constants/redis.constant'

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name)

  constructor(@Inject(IORedisKey) private readonly redisClient: Redis) {}

  onModuleInit() {
    this.logger.log('Redis client connected')
  }

  onModuleDestroy() {
    this.redisClient.disconnect()
    this.logger.log('Redis client disconnected')
  }

  get client(): Redis {
    return this.redisClient
  }

  // --- Core Methods ---
  async set(key: RedisKey, value: RedisValue, ttlSeconds?: number): Promise<'OK'> {
    if (ttlSeconds) {
      return this.redisClient.set(key, value, 'EX', ttlSeconds)
    }
    return this.redisClient.set(key, value)
  }

  async get(key: RedisKey): Promise<string | null> {
    return this.redisClient.get(key)
  }

  async del(keys: RedisKey | RedisKey[]): Promise<number> {
    const keysToDelete = Array.isArray(keys) ? keys : [keys]
    if (keysToDelete.length === 0) return 0
    return this.redisClient.del(keysToDelete)
  }

  // --- JSON Helpers ---
  async setJson(key: RedisKey, value: any, ttlSeconds?: number): Promise<'OK'> {
    const jsonString = JSON.stringify(value)
    return this.set(key, jsonString, ttlSeconds)
  }

  async getJson<T>(key: RedisKey): Promise<T | null> {
    const jsonString = await this.get(key)
    if (!jsonString) return null
    try {
      return JSON.parse(jsonString) as T
    } catch (error) {
      this.logger.error(`Failed to parse JSON for key "${String(key)}"`, error)
      return null
    }
  }

  // --- Key Management ---
  async keys(pattern: string): Promise<string[]> {
    return this.redisClient.keys(pattern)
  }

  async exists(keys: RedisKey[]): Promise<number> {
    if (keys.length === 0) return 0
    return this.redisClient.exists(keys)
  }
}
