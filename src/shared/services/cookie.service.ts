import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { CookieOptions, Response } from 'express'

// Định nghĩa một kiểu dữ liệu cho các key của các cookie đã được cấu hình.
// Điều này giúp tăng cường type-safety và tự động gợi ý code.
export type CookieDefinitionKey = 'accessToken' | 'refreshToken' | 'csrfSecret' | 'csrfToken'

@Injectable()
export class CookieService {
  private readonly logger = new Logger(CookieService.name)

  constructor(private readonly configService: ConfigService) {}

  /**
   * Phương thức chung để thiết lập bất kỳ cookie nào đã được định nghĩa trong file cấu hình.
   * Tự động xử lý các prefix bảo mật (__Host-) và tất cả các tùy chọn khác.
   * @param res Đối tượng Response của Express.
   * @param key Tên logic của cookie (ví dụ: 'accessToken').
   * @param value Giá trị của cookie.
   * @param options Các tùy chọn bổ sung hoặc ghi đè lên cấu hình mặc định.
   */
  set(res: Response, key: CookieDefinitionKey, value: string, options: Partial<CookieOptions> = {}): void {
    const definition = this.configService.get(`cookie.definitions.${key}`)
    if (!definition) {
      this.logger.error(`Không tìm thấy cấu hình cho cookie với key: "${key}".`)
      return
    }

    const cookieName = `${definition.prefix}${definition.name}`
    const finalOptions = { ...definition.options, ...options }

    res.cookie(cookieName, value, finalOptions)
  }

  /**
   * Phương thức chung để xóa bất kỳ cookie nào đã được định nghĩa.
   * @param res Đối tượng Response của Express.
   * @param key Tên logic của cookie cần xóa.
   */
  clear(res: Response, key: CookieDefinitionKey): void {
    const definition = this.configService.get(`cookie.definitions.${key}`)
    if (!definition) {
      this.logger.error(`Không tìm thấy cấu hình cho cookie với key: "${key}".`)
      return
    }

    const cookieName = `${definition.prefix}${definition.name}`
    // Để xóa cookie, phải cung cấp chính xác path và domain đã dùng để set.
    const clearOptions = {
      path: definition.options.path,
      domain: definition.options.domain,
    }
    res.clearCookie(cookieName, clearOptions)
  }

  // --- Các phương thức tiện ích ---

  /**
   * Thiết lập cả hai cookie access và refresh token cùng một lúc.
   */
  setTokenCookies(res: Response, accessToken: string, refreshToken: string, rememberMe: boolean = false): void {
    this.set(res, 'accessToken', accessToken)

    // Áp dụng logic "remember me" cho thời gian sống của refresh token
    const refreshTokenMaxAge = rememberMe
      ? this.configService.get<number>('cookie.rememberMeMaxAge')
      : this.configService.get<number>('cookie.refreshTokenMaxAge')

    this.set(res, 'refreshToken', refreshToken, { maxAge: refreshTokenMaxAge })
  }

  /**
   * Xóa cả hai cookie access và refresh token.
   */
  clearTokenCookies(res: Response): void {
    this.clear(res, 'accessToken')
    this.clear(res, 'refreshToken')
  }
}
