import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { Response } from 'express'

interface IErrorResponse {
  statusCode: number
  code: string
  message: string
  details?: any
}

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name)

  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost
    const ctx = host.switchToHttp()
    const response = ctx.getResponse<Response>()
    const request = ctx.getRequest<Request>()

    let errorResponse: IErrorResponse

    if (exception instanceof ApiException) {
      errorResponse = {
        statusCode: exception.getStatus(),
        code: exception.code,
        message: exception.message, // This would be the i18n key
        details: exception.details,
      }
    } else if (exception instanceof HttpException) {
      const status = exception.getStatus()
      const resp = exception.getResponse()
      errorResponse = {
        statusCode: status,
        code: `HTTP_${status}`,
        message: typeof resp === 'string' ? resp : (resp as any).message || 'Http Exception',
        details: typeof resp === 'string' ? undefined : resp,
      }
    } else {
      errorResponse = {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        code: 'INTERNAL_SERVER_ERROR',
        message: 'An internal server error occurred',
        details: process.env.NODE_ENV !== 'production' ? (exception as Error).stack : undefined,
      }
    }

    this.logger.error(
      `[${request.method} ${request.url}] - Status: ${errorResponse.statusCode} - Code: ${errorResponse.code}`,
      JSON.stringify(errorResponse.details),
      (exception as Error).stack,
    )

    httpAdapter.reply(response, errorResponse, errorResponse.statusCode)
  }
}
