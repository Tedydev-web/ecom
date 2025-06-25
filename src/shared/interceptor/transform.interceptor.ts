import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'
import { I18nTranslations } from 'src/generated/i18n.generated'

export interface Response<T> {
  data: T
}

@Injectable()
export class TransformInterceptor<T> implements NestInterceptor<T, Response<T>> {
  constructor(private readonly i18n: I18nService<I18nTranslations>) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<Response<T>> {
    return next.handle().pipe(
      map((data) => {
        if (data && typeof data === 'object' && 'message' in data && typeof data.message === 'string') {
          data.message = this.i18n.t(data.message as any, {
            lang: context.switchToHttp().getRequest().i18nLang,
          })
        }
        return data
      }),
    )
  }
}
