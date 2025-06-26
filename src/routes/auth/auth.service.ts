import { HttpException, Injectable, ForbiddenException, UnauthorizedException, HttpStatus } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { addMilliseconds } from 'date-fns'
import {
  DisableTwoFactorBodyType,
  ForgotPasswordBodyType,
  LoginBodyType,
  RefreshTokenBodyType,
  RegisterBodyType,
  SendOTPBodyType,
} from 'src/routes/auth/auth.model'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { RolesService } from 'src/routes/auth/roles.service'
import { generateOTP, isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { TokenService } from 'src/shared/services/token.service'
import ms from 'ms'
import envConfig from 'src/shared/config'
import { TypeOfVerificationCode, TypeOfVerificationCodeType } from 'src/shared/constants/auth.constant'
import { EmailService } from 'src/shared/services/email.service'
import { AccessTokenPayloadCreate } from 'src/shared/types/jwt.type'
import { AuthError } from 'src/routes/auth/auth.error'
import { TwoFactorService } from 'src/shared/services/2fa.service'
import { CookieService } from 'src/shared/services/cookie.service'
import { Response } from 'express'
import { UserType } from 'src/shared/models/shared-user.model'
import { GlobalError } from 'src/shared/global.error'
import { SessionService } from 'src/shared/services/session.service'
import { UserAgentService } from 'src/shared/services/user-agent.service'

interface RefreshTokenInput {
  refreshToken: string | undefined
  userAgent: string
  ip: string
  res: Response
}

@Injectable()
export class AuthService {
  constructor(
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly authRepository: AuthRepository,
    private readonly sharedUserRepository: SharedUserRepository,
    private readonly emailService: EmailService,
    private readonly tokenService: TokenService,
    private readonly twoFactorService: TwoFactorService,
    private readonly cookieService: CookieService,
    private readonly configService: ConfigService,
    private readonly sessionService: SessionService,
    private readonly userAgentService: UserAgentService,
  ) {}

  async validateVerificationCode({
    email,
    code,
    type,
  }: {
    email: string
    code: string
    type: TypeOfVerificationCodeType
  }) {
    const vevificationCode = await this.authRepository.findUniqueVerificationCode({
      email_code_type: {
        email,
        code,
        type,
      },
    })
    if (!vevificationCode) {
      throw AuthError.InvalidOTP
    }
    if (vevificationCode.expiresAt < new Date()) {
      await this.authRepository.deleteVerificationCode({ id: vevificationCode.id })
      throw AuthError.OTPExpired
    }
    return vevificationCode
  }
  async register(body: RegisterBodyType) {
    try {
      await this.validateVerificationCode({
        email: body.email,
        code: body.code,
        type: TypeOfVerificationCode.REGISTER,
      })
      const clientRoleId = await this.rolesService.getClientRoleId()
      const hashedPassword = await this.hashingService.hash(body.password)
      const [user] = await Promise.all([
        this.authRepository.createUser({
          email: body.email,
          name: body.name,
          phoneNumber: body.phoneNumber,
          password: hashedPassword,
          roleId: clientRoleId,
        }),
        this.authRepository.deleteVerificationCode({
          email_code_type: {
            email: body.email,
            code: body.code,
            type: TypeOfVerificationCode.REGISTER,
          },
        }),
      ])
      return user
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw AuthError.EmailAlreadyExists
      }
      throw error
    }
  }

  async sendOTP(body: SendOTPBodyType) {
    const user = await this.sharedUserRepository.findUnique({
      email: body.email,
    })
    if (body.type === TypeOfVerificationCode.REGISTER && user) {
      throw AuthError.EmailAlreadyExists
    }
    if (body.type === TypeOfVerificationCode.FORGOT_PASSWORD && !user) {
      throw AuthError.EmailNotFound
    }
    const code = generateOTP()
    await this.authRepository.createVerificationCode({
      email: body.email,
      code,
      type: body.type,
      expiresAt: addMilliseconds(new Date(), this.configService.get<number>('otp.expiresInMs')!),
    })
    const { error } = await this.emailService.sendOTP({
      email: body.email,
      code,
    })
    if (error) {
      throw AuthError.FailedToSendOTP
    }
    return { message: 'auth.success.OTP_SENT' }
  }

  async login(body: LoginBodyType & { userAgent: string; ip: string }, res: Response) {
    // 1. Lấy thông tin user, kiểm tra user có tồn tại hay không, mật khẩu có đúng không
    const userWithCount = await this.authRepository.findUniqueUserIncludeRole({
      email: body.email,
    })

    if (!userWithCount) {
      throw AuthError.EmailNotFound
    }

    const isPasswordMatch = await this.hashingService.compare(body.password, userWithCount.password)
    if (!isPasswordMatch) {
      throw AuthError.InvalidPassword
    }
    // 2. Nếu user đã bật mã 2FA thì kiểm tra mã 2FA TOTP Code hoặc OTP Code (email)
    if (userWithCount.totpSecret) {
      // Nếu không có mã TOTP Code và Code thì thông báo cho client biết
      if (!body.totpCode && !body.code) {
        throw AuthError.InvalidTOTPAndCode
      }

      // Kiểm tra TOTP Code có hợp lệ hay không
      if (body.totpCode) {
        const isValid = this.twoFactorService.verifyTOTP({
          secret: userWithCount.totpSecret,
          token: body.totpCode,
        })
        if (!isValid) {
          throw AuthError.InvalidTOTP
        }
      } else if (body.code) {
        // Kiểm tra mã OTP có hợp lệ không
        await this.validateVerificationCode({
          email: userWithCount.email,
          code: body.code,
          type: TypeOfVerificationCode.LOGIN,
        })
      }
    }

    // 3. Phân tích user agent để lấy thông tin thiết bị
    const parsedUserAgent = this.userAgentService.parse(body.userAgent)

    // 4. Upsert (tạo hoặc cập nhật) thiết bị
    const device = await this.authRepository.upsertDevice({
      userId: userWithCount.id,
      lastIp: body.ip,
      browser: parsedUserAgent.browser,
      os: parsedUserAgent.os,
      type: parsedUserAgent.deviceType,
      // fingerprint sẽ được triển khai ở giai đoạn sau để tăng độ chính xác
    })

    // 5. Tính toán thời gian hết hạn cho Refresh Token
    const refreshTokenExpiresInMs = this.configService.get<number>('jwt.refreshToken.expiresInMs')!
    const refreshTokenExpiresAt = addMilliseconds(new Date(), refreshTokenExpiresInMs)

    // 6. Tạo một phiên đăng nhập (session) mới
    const session = await this.authRepository.createSession({
      userId: userWithCount.id,
      deviceId: device.id,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      expiresAt: refreshTokenExpiresAt,
    })

    // 7. Tạo mới accessToken và refreshToken với sessionId
    const { accessToken, refreshToken } = await this.generateTokens({
      userId: userWithCount.id,
      sessionId: session.id,
      roleId: userWithCount.roleId,
      roleName: userWithCount.role.name,
    })

    // 8. Set tokens vào cookie, có kiểm tra "rememberMe"
    this.cookieService.setTokenCookies(res, accessToken, refreshToken, body.rememberMe)

    // 9. Bỏ các trường nhạy cảm khỏi object user trả về
    const { password, totpSecret, _count, ...userWithoutSensitiveData } = userWithCount
    return userWithoutSensitiveData
  }

  async generateTokens({ userId, sessionId, roleId, roleName }: AccessTokenPayloadCreate) {
    const [accessToken, refreshToken] = await Promise.all([
      this.tokenService.signAccessToken({
        userId,
        sessionId,
        roleId,
        roleName,
      }),
      this.tokenService.signRefreshToken({
        userId,
        sessionId,
      }),
    ])
    return { accessToken, refreshToken }
  }

  async refreshToken({ refreshToken, userAgent, ip, res }: RefreshTokenInput) {
    if (!refreshToken) {
      this.cookieService.clearTokenCookies(res)
      throw AuthError.RefreshTokenRequired
    }

    // 1. Xác thực RT và lấy payload
    const { jti, userId, sessionId } = await this.tokenService.verifyRefreshToken(refreshToken).catch(() => {
      this.cookieService.clearTokenCookies(res)
      throw AuthError.InvalidRefreshToken
    })

    // 2. Kiểm tra token tái sử dụng (replay attack)
    const isUsed = await this.sessionService.isRefreshTokenUsed(jti)
    if (isUsed) {
      // TODO: Vô hiệu hóa tất cả các phiên của người dùng này như một biện pháp bảo mật
      throw AuthError.RefreshTokenReused
    }

    // Đánh dấu ngay lập tức là đã sử dụng để tránh race condition
    await this.sessionService.markRefreshTokenAsUsed(jti)

    // 3. Lấy thông tin session và user từ DB
    const session = await this.authRepository.findValidSessionById(sessionId)

    // 4. Thực hiện các kiểm tra bảo mật
    if (!session || session.userId !== userId) {
      this.cookieService.clearTokenCookies(res)
      throw AuthError.InvalidRefreshToken // Lỗi chung cho các trường hợp không hợp lệ
    }
    // `findValidSessionById` đã kiểm tra revokedAt và expiresAt

    if (session.user.revokedAllSessionsBefore && session.createdAt < session.user.revokedAllSessionsBefore) {
      this.cookieService.clearTokenCookies(res)
      throw AuthError.SessionRevoked
    }

    if (session.user.status !== 'ACTIVE') {
      this.cookieService.clearTokenCookies(res)
      throw AuthError.UserNotActive
    }

    // 5. Cập nhật hoạt động của phiên và tạo token mới
    const updatedSession = await this.authRepository.updateSessionLastActive(sessionId)
    const tokens = await this.generateTokens({
      userId: session.user.id,
      sessionId: updatedSession.id,
      roleId: session.user.roleId,
      roleName: session.user.role.name,
    })

    // 6. Set cookie mới
    this.cookieService.setTokenCookies(res, tokens.accessToken, tokens.refreshToken, true)

    res.status(HttpStatus.OK).send({ message: 'auth.success.REFRESH_TOKEN_SUCCESS' })
  }

  async logout(refreshToken: string | undefined, res: Response) {
    if (refreshToken) {
      try {
        const { sessionId, exp, jti } = await this.tokenService.verifyRefreshToken(refreshToken)
        const remainingTime = exp - Math.floor(Date.now() / 1000)

        // Hành động chính: Vô hiệu hóa session trong DB
        await this.authRepository.revokeSession(sessionId)

        // Hành động phụ: Blacklist JTI trong Redis để có hiệu lực tức thì
        if (remainingTime > 0) {
          await this.sessionService.addToBlacklist(jti, remainingTime)
        }
      } catch (error) {
        // Bỏ qua lỗi nếu token không hợp lệ, vì mục tiêu là đăng xuất
      }
    }

    this.cookieService.clearTokenCookies(res)
    return { message: 'auth.success.LOGOUT_SUCCESS' }
  }

  async forgotPassword(body: ForgotPasswordBodyType) {
    const { email } = body
    const user = await this.sharedUserRepository.findUnique({ email })
    if (!user) {
      // Don't reveal that the user does not exist
      return { message: 'auth.success.FORGOT_PASSWORD_SENT' }
    }
    const code = generateOTP()
    await this.emailService.sendOTP({
      email,
      code,
    })
    await this.authRepository.createVerificationCode({
      email: body.email,
      code,
      type: TypeOfVerificationCode.FORGOT_PASSWORD,
      expiresAt: addMilliseconds(new Date(), this.configService.get<number>('otp.expiresInMs')!),
    })
    return { message: 'auth.success.FORGOT_PASSWORD_SENT' }
  }

  async setupTwoFactorAuth(userId: number) {
    // 1. Lấy thông tin user, kiểm tra xem user có tồn tại hay không, và xem họ đã bật 2FA chưa
    const user = await this.sharedUserRepository.findUnique({
      id: userId,
    })
    if (!user) {
      throw AuthError.UserNotFound
    }
    if (user.totpSecret) {
      throw AuthError.TOTPAlreadyEnabled
    }
    // 2. Tạo ra secret và uri
    const { secret, uri } = this.twoFactorService.generateTOTPSecret(user.email)
    // 3. Cập nhật secret vào user trong database
    await this.authRepository.updateUser({ id: userId }, { totpSecret: secret })
    // 4. Trả về secret và uri
    return {
      secret,
      uri,
    }
  }

  async disableTwoFactorAuth(data: DisableTwoFactorBodyType & { userId: number }) {
    const { userId, totpCode, code } = data
    // 1. Lấy thông tin user, kiểm tra xem user có tồn tại hay không, và xem họ đã bật 2FA chưa
    const user = await this.sharedUserRepository.findUnique({ id: userId })
    if (!user) {
      throw AuthError.UserNotFound
    }
    if (!user.totpSecret) {
      throw AuthError.TOTPNotEnabled
    }

    // 2. Kiểm tra mã TOTP có hợp lệ hay không
    if (totpCode) {
      const isValid = this.twoFactorService.verifyTOTP({
        secret: user.totpSecret,
        token: totpCode,
      })
      if (!isValid) {
        throw AuthError.InvalidTOTP
      }
    } else if (code) {
      // 3. Kiểm tra mã OTP email có hợp lệ hay không
      await this.validateVerificationCode({
        email: user.email,
        code,
        type: TypeOfVerificationCode.DISABLE_2FA,
      })
    } else {
      // Nếu không có mã nào được cung cấp
      throw AuthError.Disable2FARequiresCode
    }

    // 4. Cập nhật secret thành null
    await this.authRepository.updateUser({ id: userId }, { totpSecret: null })

    // 5. Trả về thông báo
    return {
      message: 'auth.success.DISABLE_2FA_SUCCESS',
    }
  }
}
