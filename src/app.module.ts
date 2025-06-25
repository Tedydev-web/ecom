import { Module } from '@nestjs/common'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { SharedModule } from 'src/shared/shared.module'
import { AuthModule } from 'src/routes/auth/auth.module'
import { APP_FILTER, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core'
import CustomZodValidationPipe from 'src/shared/pipes/custom-zod-validation.pipe'
import { ZodSerializerInterceptor } from 'nestjs-zod'
import { AllExceptionsFilter } from 'src/shared/filters/all-exceptions.filter'
import { LanguageModule } from 'src/routes/language/language.module'
import { ConfigModule } from '@nestjs/config'
import config from 'src/shared/config'

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: config,
      // cache: true, // You can enable caching in production
    }),
    SharedModule,
    AuthModule,
    LanguageModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_PIPE,
      useClass: CustomZodValidationPipe,
    },
    { provide: APP_INTERCEPTOR, useClass: ZodSerializerInterceptor },
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter,
    },
  ],
})
export class AppModule {}
