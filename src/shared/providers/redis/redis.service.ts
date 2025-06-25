import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common'
import Redis, { RedisKey, RedisValue } from 'ioredis'
import { IORedisKey } from './redis.constants'
import { IRedisService } from './redis.interface'

@Injectable()
export class RedisService implements IRedisService, OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name)

  constructor(@Inject(IORedisKey) public readonly client: Redis) {}

  onModuleInit() {
    this.logger.log('Redis client connected')
  }

  onModuleDestroy() {
    this.client.disconnect()
    this.logger.log('Redis client disconnected')
  }

  async set(key: RedisKey, value: any, ttlSeconds?: number): Promise<'OK'> {
    const serializedValue = JSON.stringify(value)
    if (ttlSeconds) {
      return this.client.set(key, serializedValue, 'EX', ttlSeconds)
    }
    return this.client.set(key, serializedValue)
  }

  async get<T>(key: RedisKey): Promise<T | null> {
    const value = await this.client.get(key)
    return value ? (JSON.parse(value) as T) : null
  }

  async del(keys: RedisKey | RedisKey[]): Promise<number> {
    const keysToDelete = Array.isArray(keys) ? keys : [keys]
    if (keysToDelete.length === 0) return 0
    return this.client.del(keysToDelete)
  }

  async hset(key: RedisKey, field: string, value: any): Promise<number> {
    return this.client.hset(key, field, JSON.stringify(value))
  }

  async hget<T>(key: RedisKey, field: string): Promise<T | null> {
    const value = await this.client.hget(key, field)
    return value ? (JSON.parse(value) as T) : null
  }

  async hgetall<T>(key: RedisKey): Promise<T | null> {
    const value = await this.client.hgetall(key)
    if (!value || Object.keys(value).length === 0) return null
    const deserialized = Object.entries(value).reduce(
      (acc, [key, val]) => {
        acc[key] = JSON.parse(val)
        return acc
      },
      {} as Record<string, any>,
    )
    return deserialized as T
  }

  async sadd(key: RedisKey, members: any | any[]): Promise<number> {
    const membersToAdd = (Array.isArray(members) ? members : [members]).map((m) => JSON.stringify(m))
    return this.client.sadd(key, ...membersToAdd)
  }

  async sismember(key: RedisKey, member: any): Promise<number> {
    return this.client.sismember(key, JSON.stringify(member))
  }

  async smembers<T>(key: RedisKey): Promise<T[]> {
    const members = await this.client.smembers(key)
    return members.map((m) => JSON.parse(m) as T)
  }

  async lpush(key: RedisKey, elements: any | any[]): Promise<number> {
    const elementsToPush = (Array.isArray(elements) ? elements : [elements]).map((el) => JSON.stringify(el))
    return this.client.lpush(key, ...elementsToPush)
  }

  async lrange<T>(key: RedisKey, start: number, stop: number): Promise<T[]> {
    const elements = await this.client.lrange(key, start, stop)
    return elements.map((el) => JSON.parse(el) as T)
  }

  async exists(keys: RedisKey[]): Promise<number> {
    if (keys.length === 0) return 0
    return this.client.exists(keys)
  }

  async keys(pattern: string): Promise<string[]> {
    return this.client.keys(pattern)
  }

  async pipeline(commands: (string | number | Buffer)[][]): Promise<[error: Error | null, result: unknown][] | null> {
    const pipeline = this.client.pipeline(commands)
    return pipeline.exec()
  }
}
