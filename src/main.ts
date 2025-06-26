import { HttpAdapterHost, NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import cookieParser from 'cookie-parser'
import { ConfigService } from '@nestjs/config'
import { AllExceptionsFilter } from './shared/filters/all-exceptions.filter'
import { I18nService } from 'nestjs-i18n'
import { CookieService } from './shared/services/cookie.service'
import { I18nTranslations } from './generated/i18n.generated'

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  const configService = app.get(ConfigService)
  const port = configService.get<number>('app.port')!
  const httpAdapterHost = app.get(HttpAdapterHost)
  const i18nService = app.get<I18nService<I18nTranslations>>(I18nService)
  const cookieService = app.get(CookieService)

  app.useGlobalFilters(new AllExceptionsFilter(httpAdapterHost, i18nService, cookieService))
  app.enableCors()
  app.use(cookieParser())
  await app.listen(port)
}
bootstrap()
