import { Injectable, NestMiddleware, Logger } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import csurf from 'csurf'
import { ConfigService } from '@nestjs/config'

@Injectable()
export class CsrfProtectionMiddleware implements NestMiddleware {
  private readonly logger = new Logger(CsrfProtectionMiddleware.name)
  private readonly csurfProtection: (req: Request, res: Response, next: NextFunction) => void

  constructor(private readonly configService: ConfigService) {
    this.csurfProtection = csurf({
      cookie: {
        httpOnly: true,
        secure: this.configService.get<boolean>('cookie.secure'),
        sameSite: this.configService.get('cookie.sameSite'),
        path: this.configService.get<string>('cookie.path'),
        domain: this.configService.get<string>('cookie.domain'),
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
        // Thay vì throw ForbiddenException, chúng ta sẽ để cho AllExceptionsFilter xử lý
        return next(err)
      }
      const token = req.csrfToken()
      // Set cookie XSRF-TOKEN mà client có thể đọc được để gửi lại trong header
      res.cookie('XSRF-TOKEN', token, {
        secure: this.configService.get<boolean>('cookie.secure'),
        sameSite: this.configService.get('cookie.sameSite'),
        path: this.configService.get<string>('cookie.path'),
        domain: this.configService.get<string>('cookie.domain'),
        httpOnly: false, // Quan trọng: Phải là false để JS ở client đọc được
      })
      next()
    })
  }
}
