import { Redis } from 'ioredis'

export interface IRedisService {
  readonly client: Redis

  set(key: string, value: any, ttlSeconds?: number): Promise<'OK'>
  get<T>(key: string): Promise<T | null>
  del(keys: string | string[]): Promise<number>

  hset(key: string, field: string, value: any): Promise<number>
  hget<T>(key: string, field: string): Promise<T | null>
  hgetall<T>(key: string): Promise<T | null>

  sadd(key: string, members: any | any[]): Promise<number>
  sismember(key: string, member: any): Promise<number>
  smembers<T>(key: string): Promise<T[]>

  lpush(key: string, elements: any | any[]): Promise<number>
  lrange<T>(key: string, start: number, stop: number): Promise<T[]>

  exists(keys: string[]): Promise<number>
  keys(pattern: string): Promise<string[]>

  pipeline(commands: (string | number | Buffer)[][]): Promise<[error: Error | null, result: unknown][] | null>
}
