import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger, Inject } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { Response, Request } from 'express'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { ZodError } from 'zod'
import { CookieService } from '../services/cookie.service'
import * as tokens from 'src/shared/constants/injection.tokens'

interface IErrorResponse {
  success: false
  statusCode: number
  code: string
  message: string
  details?: any
}

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name)

  constructor(
    private readonly httpAdapterHost: HttpAdapterHost,
    private readonly i18n: I18nService<I18nTranslations>,
    @Inject(tokens.COOKIE_SERVICE) private readonly cookieService: CookieService,
  ) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost
    const ctx = host.switchToHttp()
    const response = ctx.getResponse<Response>()
    const request = ctx.getRequest<Request>()
    const lang = I18nContext.current()?.lang

    let statusCode: HttpStatus
    let code: string
    let message: string
    let details: any

    if (exception && (exception as any).code === 'EBADCSRFTOKEN') {
      statusCode = HttpStatus.FORBIDDEN
      code = 'INVALID_CSRF_TOKEN'
      message = this.i18n.t('global.error.INVALID_CSRF_TOKEN' as any, { lang })
      details = 'CSRF token is invalid or missing.'
    } else if (exception instanceof ApiException) {
      statusCode = exception.getStatus()
      code = exception.code
      message = this.i18n.t(exception.message as any, {
        lang,
        args: exception.details,
      })
      details = exception.details
    } else if (exception instanceof ZodError) {
      statusCode = HttpStatus.UNPROCESSABLE_ENTITY
      code = 'VALIDATION_FAILED'
      message = this.i18n.t('global.error.VALIDATION_FAILED' as any, { lang })
      details = exception.flatten()
    } else if (exception instanceof HttpException) {
      statusCode = exception.getStatus()
      const exceptionResponse = exception.getResponse()
      code = `HTTP_${statusCode}`
      if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
        message = (exceptionResponse as any).message || exception.message
        details = exceptionResponse
      } else {
        message = exceptionResponse || exception.message
      }
    } else {
      statusCode = HttpStatus.INTERNAL_SERVER_ERROR
      code = 'INTERNAL_SERVER_ERROR'
      message = this.i18n.t('global.error.INTERNAL_SERVER_ERROR', { lang })
      details = process.env.NODE_ENV !== 'production' ? (exception as Error).stack : undefined
    }

    const responseBody: IErrorResponse = {
      success: false,
      statusCode,
      code,
      message,
      details,
    }

    this.logError(request, responseBody, exception)
    this.handleAuthCookies(statusCode, response)

    httpAdapter.reply(response, responseBody, statusCode)
  }

  private logError(request: Request, errorResponse: IErrorResponse, exception: unknown) {
    const { method, url } = request
    const { statusCode, code, details } = errorResponse
    const errorDetails = JSON.stringify(details)
    const stack = (exception as Error).stack

    this.logger.error(`[${method} ${url}] - Status: ${statusCode} - Code: ${code} - Details: ${errorDetails}`, stack)
  }

  private handleAuthCookies(statusCode: number, response: Response) {
    // Nếu lỗi là do không được phép (Unauthorized), xóa cookie để buộc người dùng đăng nhập lại.
    // Điều này tăng cường bảo mật, tránh trường hợp cookie cũ vẫn được lưu trên trình duyệt.
    if (statusCode === 401) {
      this.cookieService.clearTokenCookies(response)
    }
  }
}
