import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { JwtService } from '@nestjs/jwt'
import {
  AccessTokenPayload,
  AccessTokenPayloadCreate,
  RefreshTokenPayload,
  RefreshTokenPayloadCreate,
} from 'src/shared/types/jwt.type'
import { v4 as uuidv4 } from 'uuid'

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  signAccessToken(payload: AccessTokenPayloadCreate) {
    return this.jwtService.sign(
      { ...payload, uuid: uuidv4() },
      {
        secret: this.configService.get<string>('jwt.accessToken.secret'),
        expiresIn: this.configService.get<string>('jwt.accessToken.expiresIn'),
        algorithm: 'HS256',
      },
    )
  }

  signRefreshToken(payload: RefreshTokenPayloadCreate) {
    return this.jwtService.sign(
      { ...payload, uuid: uuidv4() },
      {
        secret: this.configService.get<string>('jwt.refreshToken.secret'),
        expiresIn: this.configService.get<string>('jwt.refreshToken.expiresIn'),
        algorithm: 'HS256',
      },
    )
  }

  verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    return this.jwtService.verifyAsync(token, {
      secret: this.configService.get<string>('jwt.accessToken.secret'),
    })
  }

  verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
    return this.jwtService.verifyAsync(token, {
      secret: this.configService.get<string>('jwt.refreshToken.secret'),
    })
  }
}
