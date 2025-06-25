import { HttpStatus } from '@nestjs/common'
import { ApiException } from './exceptions/api.exception'

/**
 * Provides static methods for creating common API exceptions.
 */
export class GlobalError {
  public static InternalServerError(message: string = 'error.INTERNAL_SERVER_ERROR', details?: any): ApiException {
    return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'E0001', message, details)
  }

  public static BadRequest(message: string = 'error.BAD_REQUEST', details?: any): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'E0002', message, details)
  }

  public static Unauthorized(message: string = 'error.UNAUTHORIZED', details?: any): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'E0003', message, details)
  }

  public static Forbidden(message: string = 'error.FORBIDDEN', details?: any): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'E0004', message, details)
  }

  public static NotFound(entity: string = 'resource', details?: any): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'E0005', `error.${entity.toUpperCase()}_NOT_FOUND`, details)
  }

  public static UnprocessableEntity(message: string = 'error.UNPROCESSABLE_ENTITY', details?: any): ApiException {
    return new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, 'E0006', message, details)
  }
} 