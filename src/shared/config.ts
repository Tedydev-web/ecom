import { registerAs } from '@nestjs/config'
import { config } from 'dotenv'
import { z } from 'zod'
import ms from 'ms'
import { CookieNames } from './constants/cookie.constant'

config({
  path: '.env',
})

const AppConfigSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  APP_NAME: z.string().default('Shopsifu'),
  API_KEY: z.string(),
  CLIENT_URL: z.string().url(),
  EMAIL_FROM: z.string().email().default('noreply@shopsifu.com'),
})

const CsrfConfigSchema = z.object({
  CSRF_SECRET_LENGTH: z.coerce.number().int().positive().default(32),
  CSRF_HEADER_NAME: z.string().default('x-csrf-token'),
})

const JWTConfigSchema = z.object({
  ACCESS_TOKEN_SECRET: z.string(),
  ACCESS_TOKEN_EXPIRES_IN: z.string().default('15m'),
  REFRESH_TOKEN_SECRET: z.string(),
  REFRESH_TOKEN_EXPIRES_IN: z.string().default('7d'),
})

const CookieConfigSchema = z.object({
  COOKIE_SECRET: z.string(),
})

const DatabaseConfigSchema = z.object({
  DATABASE_URL: z.string(),
})

const GoogleConfigSchema = z.object({
  GOOGLE_CLIENT_ID: z.string(),
  GOOGLE_CLIENT_SECRET: z.string(),
  GOOGLE_REDIRECT_URI: z.string().url(),
})

const OTPConfigSchema = z.object({
  OTP_EXPIRES_IN: z.string().default('5m'),
})

const AdminConfigSchema = z.object({
  ADMIN_NAME: z.string(),
  ADMIN_PASSWORD: z.string(),
  ADMIN_EMAIL: z.string().email(),
  ADMIN_PHONE_NUMBER: z.string(),
})

const ResendConfigSchema = z.object({
  RESEND_API_KEY: z.string(),
})

const RedisConfigSchema = z.object({
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.coerce.number().int().positive().default(6379),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.coerce.number().int().default(0),
})

const RootConfigSchema = AppConfigSchema.merge(JWTConfigSchema)
  .merge(CookieConfigSchema)
  .merge(DatabaseConfigSchema)
  .merge(GoogleConfigSchema)
  .merge(OTPConfigSchema)
  .merge(AdminConfigSchema)
  .merge(ResendConfigSchema)
  .merge(CsrfConfigSchema)
  .merge(RedisConfigSchema)

const validatedConfig = RootConfigSchema.parse(process.env)

export const envConfig = validatedConfig

export const app = registerAs('app', () => ({
  env: validatedConfig.NODE_ENV,
  isProd: validatedConfig.NODE_ENV === 'production',
  port: validatedConfig.PORT,
  name: validatedConfig.APP_NAME,
  apiKey: validatedConfig.API_KEY,
  clientUrl: validatedConfig.CLIENT_URL,
  emailFrom: validatedConfig.EMAIL_FROM,
}))

export const csrf = registerAs('csrf', () => ({
  secretLength: validatedConfig.CSRF_SECRET_LENGTH,
  headerName: validatedConfig.CSRF_HEADER_NAME,
}))

export const jwt = registerAs('jwt', () => ({
  accessToken: {
    secret: validatedConfig.ACCESS_TOKEN_SECRET,
    expiresIn: validatedConfig.ACCESS_TOKEN_EXPIRES_IN,
    expiresInMs: ms(validatedConfig.ACCESS_TOKEN_EXPIRES_IN),
  },
  refreshToken: {
    secret: validatedConfig.REFRESH_TOKEN_SECRET,
    expiresIn: validatedConfig.REFRESH_TOKEN_EXPIRES_IN,
    expiresInMs: ms(validatedConfig.REFRESH_TOKEN_EXPIRES_IN),
  },
}))

export const cookie = registerAs('cookie', () => {
  const isProd = validatedConfig.NODE_ENV === 'production'

  // __Host- prefix yêu cầu Secure:true, Path:/ và không có Domain.
  // Chúng ta sẽ bật "secure" cho tất cả cookie để tăng cường bảo mật.
  const getBaseOptions = (prefix: '' | '__Host-') => {
    const base = {
      secure: true, // Bắt buộc cho __Host-. Chúng ta sẽ dùng cho tất cả cookie.
      sameSite: 'lax' as const,
    }

    if (prefix === '__Host-') {
      return {
        ...base,
        path: '/',
        domain: undefined, // QUAN TRỌNG: __Host- cấm thuộc tính Domain.
      }
    }
    return {
      ...base,
      path: '/',
    }
  }

  return {
    secret: validatedConfig.COOKIE_SECRET,
    definitions: {
      accessToken: {
        name: CookieNames.ACCESS_TOKEN,
        prefix: '', // Access token không dùng prefix vì có thể cần truy cập từ domain khác trong tương lai
        options: {
          ...getBaseOptions(''),
          httpOnly: true,
          maxAge: ms(validatedConfig.ACCESS_TOKEN_EXPIRES_IN),
        },
      },
      refreshToken: {
        name: CookieNames.REFRESH_TOKEN,
        prefix: isProd ? '__Host-' : '', // Tiêu chuẩn vàng cho production
        options: {
          ...getBaseOptions(isProd ? '__Host-' : ''),
          httpOnly: true,
        },
      },
      csrfSecret: {
        name: CookieNames.CSRF_SECRET,
        prefix: isProd ? '__Host-' : '', // Tiêu chuẩn vàng cho production
        options: {
          ...getBaseOptions(isProd ? '__Host-' : ''),
          httpOnly: true,
          // Không có maxAge, đây là session cookie
        },
      },
      csrfToken: {
        name: CookieNames.CSRF_TOKEN,
        prefix: '', // JS phía client cần đọc được, nên không dùng prefix
        options: {
          ...getBaseOptions(''),
          httpOnly: false,
          // Không có maxAge, đây là session cookie
        },
      },
    },
    // Các giá trị thời gian sống cho logic nghiệp vụ
    refreshTokenMaxAge: ms(validatedConfig.REFRESH_TOKEN_EXPIRES_IN),
    rememberMeMaxAge: ms('30d'),
  }
})

export const google = registerAs('google', () => ({
  clientId: validatedConfig.GOOGLE_CLIENT_ID,
  clientSecret: validatedConfig.GOOGLE_CLIENT_SECRET,
  redirectUri: validatedConfig.GOOGLE_REDIRECT_URI,
}))

export const otp = registerAs('otp', () => ({
  expiresIn: validatedConfig.OTP_EXPIRES_IN,
  expiresInMs: ms(validatedConfig.OTP_EXPIRES_IN),
}))

export const database = registerAs('database', () => ({
  url: validatedConfig.DATABASE_URL,
}))

export const resend = registerAs('resend', () => ({
  apiKey: validatedConfig.RESEND_API_KEY,
}))

export const redis = registerAs('redis', () => ({
  host: validatedConfig.REDIS_HOST,
  port: validatedConfig.REDIS_PORT,
  password: validatedConfig.REDIS_PASSWORD,
  db: validatedConfig.REDIS_DB,
}))

// Export a single object to be loaded in AppModule
export default [app, jwt, cookie, google, otp, database, resend, csrf, redis]
