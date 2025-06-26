import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Response } from 'express'
import { OAuth2Client } from 'google-auth-library'
import { google } from 'googleapis'
import { AuthError } from 'src/routes/auth/auth.error'
import { GoogleAuthStateType } from 'src/routes/auth/auth.model'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { AuthService } from 'src/routes/auth/auth.service'
import { RolesService } from 'src/routes/auth/roles.service'
import { CookieService } from 'src/shared/services/cookie.service'
import { HashingService } from 'src/shared/services/hashing.service'
import { v4 as uuidv4 } from 'uuid'
import { addMilliseconds } from 'date-fns'
import { UserAgentService } from 'src/shared/services/user-agent.service'

@Injectable()
export class GoogleService {
  private oauth2Client: OAuth2Client
  private readonly logger = new Logger(GoogleService.name)
  private readonly clientUrl: string

  constructor(
    private readonly authRepository: AuthRepository,
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
    private readonly cookieService: CookieService,
    private readonly userAgentService: UserAgentService,
  ) {
    this.oauth2Client = new google.auth.OAuth2(
      this.configService.get<string>('google.clientId'),
      this.configService.get<string>('google.clientSecret'),
      this.configService.get<string>('google.redirectUri'),
    )
    this.clientUrl = this.configService.get<string>('app.clientUrl')!
  }
  getAuthorizationUrl({ userAgent, ip }: GoogleAuthStateType) {
    const scope = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']
    // Chuyển Object sang string base64 an toàn bỏ lên url
    const stateString = Buffer.from(
      JSON.stringify({
        userAgent,
        ip,
      }),
    ).toString('base64')
    const url = this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope,
      include_granted_scopes: true,
      state: stateString,
    })
    return { url }
  }
  async googleCallback({ code, state }: { code: string; state: string }, res: Response): Promise<void> {
    try {
      let userAgent = 'Unknown'
      let ip = 'Unknown'
      // 1. Lấy state từ url an toàn
      try {
        if (state) {
          const clientInfo = JSON.parse(Buffer.from(state, 'base64').toString()) as GoogleAuthStateType
          userAgent = clientInfo.userAgent
          ip = clientInfo.ip
        }
      } catch (error) {
        this.logger.warn('Failed to parse state from Google OAuth callback', error)
      }
      // 2. Dùng code để lấy token
      const { tokens } = await this.oauth2Client.getToken(code)
      this.oauth2Client.setCredentials(tokens)

      // 3. Lấy thông tin google user
      const oauth2 = google.oauth2({
        auth: this.oauth2Client,
        version: 'v2',
      })
      const { data: googleUser } = await oauth2.userinfo.get()
      if (!googleUser.email) {
        throw AuthError.GoogleUserInfoError
      }

      // 4. Tìm hoặc tạo user
      let user = await this.authRepository.findUniqueUserIncludeRole({
        email: googleUser.email,
      })

      if (!user) {
        const clientRoleId = await this.rolesService.getClientRoleId()
        const randomPassword = uuidv4()
        const hashedPassword = await this.hashingService.hash(randomPassword)
        const createdUser = await this.authRepository.createUserInclueRole({
          email: googleUser.email,
          name: googleUser.name ?? '',
          password: hashedPassword,
          roleId: clientRoleId,
          phoneNumber: '',
          avatar: googleUser.picture ?? null,
        })
        // Manually add _count to satisfy the type checker, as createUserInclueRole does not return it.
        user = {
          ...createdUser,
          _count: {
            sessions: 0,
            devices: 0,
          },
        }
      }

      if (!user) {
        // This check is for type safety, though logic above ensures user is defined.
        throw AuthError.UserNotFound
      }

      // 5. Phân tích user agent để lấy thông tin thiết bị
      const parsedUserAgent = this.userAgentService.parse(userAgent)

      // 6. Upsert (tạo hoặc cập nhật) thiết bị
      const device = await this.authRepository.upsertDevice({
        userId: user.id,
        lastIp: ip,
        browser: parsedUserAgent.browser,
        os: parsedUserAgent.os,
        type: parsedUserAgent.deviceType,
      })

      // 7. Tính toán thời gian hết hạn cho Refresh Token
      const refreshTokenExpiresInMs = this.configService.get<number>('jwt.refreshToken.expiresInMs')!
      const refreshTokenExpiresAt = addMilliseconds(new Date(), refreshTokenExpiresInMs)

      // 8. Tạo một phiên đăng nhập (session) mới
      const session = await this.authRepository.createSession({
        userId: user.id,
        deviceId: device.id,
        ipAddress: ip,
        userAgent: userAgent,
        expiresAt: refreshTokenExpiresAt,
      })

      // 9. Tạo mới accessToken và refreshToken với sessionId
      const { accessToken, refreshToken } = await this.authService.generateTokens({
        userId: user.id,
        sessionId: session.id,
        roleId: user.roleId,
        roleName: user.role.name,
      })

      // 10. Set cookies. Google login is like "remember me" by default.
      this.cookieService.setTokenCookies(res, accessToken, refreshToken, true)

      res.redirect(this.clientUrl)
    } catch (error) {
      this.logger.error('Error in googleCallback', error)
      // Redirect to a failure page on the client for better UX
      const failureRedirectUrl = new URL('/auth/login-failure', this.clientUrl)
      failureRedirectUrl.searchParams.set('error', 'google_oauth_failed')
      res.redirect(failureRedirectUrl.toString())
    }
  }
}
