import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Inject } from '@nestjs/common'
import { Request } from 'express'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth.constant'
import { CookieNames } from 'src/shared/constants/cookie.constant'
import { TokenService } from 'src/shared/services/token.service'
import * as tokens from 'src/shared/constants/injection.tokens'

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(@Inject(tokens.TOKEN_SERVICE) private readonly tokenService: TokenService) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>()
    const accessToken = this.extractToken(request)
    if (!accessToken) {
      throw new UnauthorizedException()
    }
    try {
      const decodedAccessToken = await this.tokenService.verifyAccessToken(accessToken)
      request[REQUEST_USER_KEY] = decodedAccessToken
      return true
    } catch {
      throw new UnauthorizedException()
    }
  }

  private extractToken(request: Request): string | undefined {
    // 1. Ưu tiên lấy từ cookie
    const fromCookie = request.cookies[CookieNames.ACCESS_TOKEN]
    if (fromCookie) {
      return fromCookie
    }
    // 2. Lấy từ header nếu không có trong cookie
    const [type, token] = request.headers.authorization?.split(' ') ?? []
    return type === 'Bearer' ? token : undefined
  }
}
