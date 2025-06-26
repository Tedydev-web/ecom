import { HttpAdapterHost, NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import CustomZodValidationPipe from 'src/shared/pipes/custom-zod-validation.pipe'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { AllExceptionsFilter } from 'src/shared/filters/all-exceptions.filter'
import { ConfigService } from '@nestjs/config'
import { Logger } from '@nestjs/common'
import cookieParser from 'cookie-parser'
import { CsrfProtectionMiddleware } from 'src/shared/middleware/csrf.middleware'
import { SecurityHeadersMiddleware } from './shared/middleware/security-headers.middleware'
import { CookieService } from './shared/services/cookie.service'
import { TransformInterceptor } from './shared/interceptor/transform.interceptor'

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  const configService = app.get(ConfigService)
  const port = configService.get<number>('app.port') || 3000
  const logger = new Logger('Bootstrap')

  // Middlewares
  app.use(cookieParser())
  // Áp dụng SecurityHeadersMiddleware trước để đảm bảo các header bảo mật được set sớm nhất.
  const securityHeadersMiddleware = app.get(SecurityHeadersMiddleware)
  app.use(securityHeadersMiddleware.use.bind(securityHeadersMiddleware))

  // CORS
  app.enableCors({
    origin: configService.get<string>('app.clientUrl'),
    credentials: true,
  })

  // Global Pipes
  app.useGlobalPipes(new CustomZodValidationPipe())

  // Khởi tạo i18n service một lần
  const i18n = app.get<I18nService<I18nTranslations>>(I18nService)

  // Global Interceptors - Áp dụng TRƯỚC Filters
  app.useGlobalInterceptors(new TransformInterceptor(i18n))

  // Global Filters
  const httpAdapterHost = app.get(HttpAdapterHost)
  const cookieService = app.get(CookieService)
  app.useGlobalFilters(new AllExceptionsFilter(httpAdapterHost, i18n, cookieService))

  // Áp dụng CSRF Middleware sau các cấu hình khác
  const csrfMiddleware = app.get(CsrfProtectionMiddleware)
  app.use(csrfMiddleware.use.bind(csrfMiddleware))

  await app.listen(port)
  logger.log(`🚀 Application is running on: http://localhost:${port}`)
}
bootstrap()
