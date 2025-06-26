import { HttpAdapterHost, NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import helmet from 'helmet'
import { Logger } from '@nestjs/common'
import { AllExceptionsFilter } from 'src/shared/filters/all-exceptions.filter'
import { I18nService, I18nValidationExceptionFilter } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { useContainer } from 'class-validator'
import { TransformInterceptor } from 'src/shared/interceptor/transform.interceptor'
import { CsrfProtectionMiddleware } from './shared/middleware/csrf.middleware'
import { SecurityHeadersMiddleware } from './shared/middleware/security-headers.middleware'
import { ConfigService } from '@nestjs/config'
import cookieParser from 'cookie-parser'

async function bootstrap() {
  const app = await NestFactory.create(AppModule)

  const configService = app.get(ConfigService)

  const i18nService = app.get<I18nService<Record<string, unknown>>>(I18nService)
  const httpAdapterHost = app.get(HttpAdapterHost)

  // Cho phép class-validator sử dụng DI container của NestJS
  useContainer(app.select(AppModule), { fallbackOnErrors: true })

  // Cấu hình logging
  const logger = new Logger('Bootstrap')
  app.useLogger(logger)

  // Bật CORS
  app.enableCors({
    origin: configService.get('app.clientUrl'),
    credentials: true, // Cho phép gửi cookie qua các domain khác nhau
  })

  // Áp dụng các security headers cơ bản với Helmet
  app.use(helmet())

  // Cookie Parser
  // Chú ý: Cần có secret để csurf hoạt động đúng cách
  app.use(cookieParser(configService.get<string>('cookie.secret')))

  // CSRF Protection Middleware
  const csrfMiddleware = app.get(CsrfProtectionMiddleware)
  app.use(csrfMiddleware.use.bind(csrfMiddleware))

  // Custom Security Headers Middleware
  const securityHeadersMiddleware = app.get(SecurityHeadersMiddleware)
  app.use(securityHeadersMiddleware.use.bind(securityHeadersMiddleware))

  // Global Interceptors
  app.useGlobalInterceptors(new TransformInterceptor(i18nService))

  // Global Filters
  app.useGlobalFilters(
    new AllExceptionsFilter(i18nService),
    new I18nValidationExceptionFilter({ detailedErrors: false }),
  )

  const port = configService.get<number>('app.port') || 3000
  await app.listen(port)
  logger.log(`🚀 Application is running on: http://localhost:${port}`)
}
bootstrap()
