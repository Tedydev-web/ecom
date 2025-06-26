import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { Response } from 'express'

export interface SuccessResponse<T> {
  success: true
  statusCode: number
  message: string
  data: T
}

@Injectable()
export class TransformInterceptor<T> implements NestInterceptor<T, SuccessResponse<T>> {
  constructor(private readonly i18n: I18nService<I18nTranslations>) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<SuccessResponse<T>> {
    const ctx = context.switchToHttp()
    const response = ctx.getResponse<Response>()
    const i18nContext = I18nContext.current()

    return next.handle().pipe(
      map((data) => {
        // Nếu data đã có cấu trúc sẵn (ví dụ: { message: '...', data: ... }), thì giữ nguyên
        const responseData = data?.data ?? data
        const messageKey = data?.message ?? 'global.success.GENERAL' // Key mặc định

        const message = this.i18n.t(messageKey, {
          lang: i18nContext?.lang,
          args: data?.args, // Cho phép truyền tham số vào message
        })

        return {
          success: true,
          statusCode: response.statusCode,
          message: message,
          data: responseData,
        }
      }),
    )
  }
}
