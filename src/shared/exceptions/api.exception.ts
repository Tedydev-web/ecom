import { HttpException, HttpStatus } from '@nestjs/common'

/**
 * Defines the base exception for all API errors.
 * @param statusCode The HTTP status code.
 * @param code A machine-readable error code.
 * @param message A human-readable message, which can be an i18n key.
 * @param details Optional additional details about the error.
 */
export class ApiException extends HttpException {
  constructor(
    public readonly statusCode: HttpStatus,
    public readonly code: string, // Machine-readable error code
    public readonly message: string, // Can be an i18n key
    public readonly details?: any,
  ) {
    super(
      {
        code,
        message,
        details,
      },
      statusCode,
    )
  }
}
