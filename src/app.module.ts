import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { SharedModule } from './shared/shared.module'
import { AuthModule } from './routes/auth/auth.module'
import { APP_FILTER, APP_PIPE, APP_INTERCEPTOR } from '@nestjs/core'
import ZodValidationPipe from 'src/shared/pipes/custom-zod-validation.pipe'
import { ZodSerializerInterceptor } from 'nestjs-zod'
import { AllExceptionsFilter } from 'src/shared/filters/all-exceptions.filter'
import { LanguageModule } from 'src/routes/language/language.module'
import { ConfigModule } from '@nestjs/config'
import config from 'src/shared/config'
import { CsrfProtectionMiddleware } from 'src/shared/middleware/csrf.middleware'
import { AcceptLanguageResolver, I18nModule, QueryResolver } from 'nestjs-i18n'
import path from 'path'
import { TransformInterceptor } from './shared/interceptor/transform.interceptor'

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: config,
    }),
    I18nModule.forRoot({
      fallbackLanguage: 'en',
      loaderOptions: {
        path: path.resolve('src/i18n'),
        watch: true,
      },
      resolvers: [AcceptLanguageResolver, new QueryResolver(['lang'])],
      typesOutputPath: path.resolve('src/generated/i18n.generated.ts'),
    }),
    SharedModule,
    AuthModule,
    LanguageModule,
  ],
  controllers: [],
  providers: [
    {
      provide: APP_PIPE,
      useClass: ZodValidationPipe,
    },
    { provide: APP_INTERCEPTOR, useClass: ZodSerializerInterceptor },
    {
      provide: APP_INTERCEPTOR,
      useClass: TransformInterceptor,
    },
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(CsrfProtectionMiddleware).forRoutes('*')
  }
}
