import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { CookieOptions, Response } from 'express'
import { CookieNames } from '../constants/cookie.constant'

@Injectable()
export class CookieService {
  private readonly logger = new Logger(CookieService.name)
  private readonly accessTokenCookieName: string = CookieNames.ACCESS_TOKEN
  private readonly refreshTokenCookieName: string = CookieNames.REFRESH_TOKEN
  private readonly csrfCookieName: string = CookieNames.CSRF_TOKEN
  private readonly baseOptions: Omit<CookieOptions, 'maxAge'>

  constructor(private readonly configService: ConfigService) {
    this.baseOptions = {
      httpOnly: this.configService.get<boolean>('cookie.httpOnly'),
      secure: this.configService.get<boolean>('cookie.secure'),
      sameSite: this.configService.get('cookie.sameSite'),
      path: this.configService.get<string>('cookie.path'),
      domain: this.configService.get<string>('cookie.domain'),
    }
  }

  private setCookie(res: Response, name: string, value: string, options: CookieOptions): void {
    res.cookie(name, value, options)
  }

  private clearCookie(res: Response, name: string): void {
    res.clearCookie(name, {
      path: this.baseOptions.path,
      domain: this.baseOptions.domain,
    })
  }

  setCsrfCookie(res: Response, csrfToken: string): void {
    this.setCookie(res, this.csrfCookieName, csrfToken, {
      ...this.baseOptions,
      httpOnly: false,
      maxAge: this.configService.get<number>('cookie.refreshTokenMaxAge'),
    })
  }

  setAccessTokenCookie(res: Response, accessToken: string): void {
    this.setCookie(res, this.accessTokenCookieName, accessToken, {
      ...this.baseOptions,
      maxAge: this.configService.get<number>('cookie.maxAge'),
    })
  }

  setRefreshTokenCookie(res: Response, refreshToken: string, rememberMe: boolean = false): void {
    const maxAge = rememberMe
      ? this.configService.get<number>('cookie.rememberMeMaxAge')
      : this.configService.get<number>('cookie.refreshTokenMaxAge')

    this.setCookie(res, this.refreshTokenCookieName, refreshToken, {
      ...this.baseOptions,
      maxAge,
    })
  }

  clearAccessTokenCookie(res: Response): void {
    this.clearCookie(res, this.accessTokenCookieName)
  }

  clearRefreshTokenCookie(res: Response): void {
    this.clearCookie(res, this.refreshTokenCookieName)
  }

  clearCsrfCookie(res: Response): void {
    this.clearCookie(res, this.csrfCookieName)
  }

  setTokenCookies(res: Response, accessToken: string, refreshToken: string, rememberMe: boolean = false): void {
    this.setAccessTokenCookie(res, accessToken)
    this.setRefreshTokenCookie(res, refreshToken, rememberMe)
  }

  clearTokenCookies(res: Response): void {
    this.clearAccessTokenCookie(res)
    this.clearRefreshTokenCookie(res)
  }
}
