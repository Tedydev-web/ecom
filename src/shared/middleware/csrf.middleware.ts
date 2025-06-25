import { Injectable, NestMiddleware, ForbiddenException, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Request, Response, NextFunction } from 'express'
import { randomBytes } from 'crypto'
import { CookieService } from 'src/shared/services/cookie.service'
import { CookieNames } from 'src/shared/constants/cookie.constant'
import { InvalidCsrfTokenException } from 'src/routes/auth/csrf.error'

@Injectable()
export class CsrfProtectionMiddleware implements NestMiddleware {
  private readonly logger = new Logger(CsrfProtectionMiddleware.name)
  private readonly csrfHeaderName: string
  private readonly csrfSecretLength: number
  private readonly safeMethods = ['GET', 'HEAD', 'OPTIONS']

  constructor(
    private readonly configService: ConfigService,
    private readonly cookieService: CookieService,
  ) {
    this.csrfHeaderName = this.configService.get<string>('csrf.headerName')!
    this.csrfSecretLength = this.configService.get<number>('csrf.secretLength')!
  }

  use(req: Request, res: Response, next: NextFunction) {
    let csrfToken = req.cookies[CookieNames.CSRF_TOKEN]

    if (!csrfToken) {
      csrfToken = randomBytes(this.csrfSecretLength).toString('hex')
      this.cookieService.setCsrfCookie(res, csrfToken)
    }

    if (this.safeMethods.includes(req.method)) {
      return next()
    }

    const tokenFromHeader = req.headers[this.csrfHeaderName] as string

    if (!tokenFromHeader) {
      this.logger.warn(`CSRF token missing from header for ${req.method} ${req.originalUrl}`)
      throw InvalidCsrfTokenException
    }

    if (tokenFromHeader !== csrfToken) {
      this.logger.warn(`Invalid CSRF token for ${req.method} ${req.originalUrl}`)
      throw InvalidCsrfTokenException
    }

    next()
  }
} 