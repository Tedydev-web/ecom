import { Injectable, NestMiddleware, Logger, Inject } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import csurf from 'csurf'
import { ConfigService } from '@nestjs/config'
import * as tokens from 'src/shared/constants/injection.tokens'
import { CookieService } from '../services/cookie.service'

@Injectable()
export class CsrfProtectionMiddleware implements NestMiddleware {
  private readonly logger = new Logger(CsrfProtectionMiddleware.name)
  private readonly csurfProtection: (req: Request, res: Response, next: NextFunction) => void

  constructor(
    private readonly configService: ConfigService,
    @Inject(tokens.COOKIE_SERVICE) private readonly cookieService: CookieService,
  ) {
    // Lấy cấu hình chi tiết cho cookie bí mật (_csrf) từ config trung tâm
    const csrfSecretConfig = this.configService.get('cookie.definitions.csrfSecret')

    this.csurfProtection = csurf({
      cookie: {
        ...csrfSecretConfig.options,
        // Cấu hình của csurf yêu cầu `signed` và `key` phải được đặt ở đây
        signed: true,
        key: csrfSecretConfig.name,
      },
      value: (req: Request) => {
        // Hỗ trợ cả hai header phổ biến mà các framework frontend hay dùng
        return (req.headers['x-csrf-token'] || req.headers['x-xsrf-token']) as string
      },
    })
  }

  use(req: Request, res: Response, next: NextFunction) {
    this.csurfProtection(req, res, (err: any) => {
      if (err) {
        this.logger.warn(`Invalid CSRF token: ${err.code}`, { url: req.originalUrl })
        // Để cho AllExceptionsFilter xử lý lỗi một cách nhất quán
        return next(err)
      }
      const token = req.csrfToken()
      // Sử dụng CookieService để set cookie XSRF-TOKEN cho client
      this.cookieService.set(res, 'csrfToken', token)

      next()
    })
  }
}
