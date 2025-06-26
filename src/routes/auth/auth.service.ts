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
    const user = await this.authRepository.findUniqueUserIncludeRole({
      email: body.email,
    })

    if (!user) {
      throw AuthError.EmailNotFound
    }

    const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
    if (!isPasswordMatch) {
      throw AuthError.InvalidPassword
    }
    // 2. Nếu user đã bật mã 2FA thì kiểm tra mã 2FA TOTP Code hoặc OTP Code (email)
    if (user.totpSecret) {
      // Nếu không có mã TOTP Code và Code thì thông báo cho client biết
      if (!body.totpCode && !body.code) {
        throw AuthError.InvalidTOTPAndCode
      }

      // Kiểm tra TOTP Code có hợp lệ hay không
      if (body.totpCode) {
        const isValid = this.twoFactorService.verifyTOTP({
          secret: user.totpSecret,
          token: body.totpCode,
        })
        if (!isValid) {
          throw AuthError.InvalidTOTP
        }
      } else if (body.code) {
        // Kiểm tra mã OTP có hợp lệ không
        await this.validateVerificationCode({
          email: user.email,
          code: body.code,
          type: TypeOfVerificationCode.LOGIN,
        })
      }
    }

    // 3. Tạo mới device
    const device = await this.authRepository.createDevice({
      userId: user.id,
      userAgent: body.userAgent,
      ip: body.ip,
    })

    // 4. Tạo mới accessToken và refreshToken
    const { accessToken, refreshToken } = await this.generateTokens({
      userId: user.id,
      deviceId: device.id,
      roleId: user.roleId,
      roleName: user.role.name,
    })

    // 5. Set tokens vào cookie
    this.cookieService.setTokenCookies(res, accessToken, refreshToken)

    // 6. Bỏ password và totpSecret khỏi object user trả về
    const { password, totpSecret, ...userWithoutSensitiveData } = user
    return userWithoutSensitiveData
  }

  async generateTokens({ userId, deviceId, roleId, roleName }: AccessTokenPayloadCreate) {
    const [accessToken, refreshToken] = await Promise.all([
      this.tokenService.signAccessToken({
        userId,
        deviceId,
        roleId,
        roleName,
      }),
      this.tokenService.signRefreshToken({
        userId,
        deviceId,
      }),
    ])
    return { accessToken, refreshToken }
  }

  async refreshToken({ refreshToken, userAgent, ip, res }: RefreshTokenInput) {
    if (!refreshToken) {
      throw AuthError.RefreshTokenRequired
    }

    const { jti, userId, deviceId } = await this.tokenService.verifyRefreshToken(refreshToken).catch(() => {
      throw AuthError.InvalidRefreshToken
    })

    const isUsed = await this.sessionService.isRefreshTokenUsed(jti)
    if (isUsed) {
      // This is a critical security event. A stolen refresh token might have been used.
      // TODO: Invalidate all active sessions for this user.
      throw AuthError.RefreshTokenReused
    }

    // Mark the refresh token as used immediately to prevent race conditions.
    await this.sessionService.markRefreshTokenAsUsed(jti)

    const user = await this.authRepository.findUniqueUserIncludeRole({ id: userId })

    if (!user) {
      this.cookieService.clearTokenCookies(res)
      throw AuthError.UserNotFound
    }

    if (user.status !== 'ACTIVE') {
      this.cookieService.clearTokenCookies(res)
      throw AuthError.UserNotActive
    }

    let device = await this.authRepository.findUniqueDevice({
      id: deviceId,
    })

    if (!device) {
      // This case is unlikely if the RT is valid, but we handle it for robustness.
      device = await this.authRepository.createDevice({
        userId: user.id,
        userAgent,
        ip,
      })
    } else {
      device = await this.authRepository.updateDevice(device.id, {
        lastActive: new Date(),
        ip,
      })
    }

    const tokens = await this.generateTokens({
      userId: user.id,
      deviceId: device.id,
      roleId: user.role.id,
      roleName: user.role.name,
    })

    this.cookieService.setTokenCookies(res, tokens.accessToken, tokens.refreshToken, true) // Always extend session on refresh

    res.status(HttpStatus.OK).send({ message: 'auth.success.REFRESH_TOKEN_SUCCESS' })
  }

  async logout(refreshToken: string | undefined, res: Response) {
    if (refreshToken) {
      try {
        const { jti, exp } = await this.tokenService.verifyRefreshToken(refreshToken)
        const remainingTime = exp - Math.floor(Date.now() / 1000)

        // Add to blacklist to prevent reuse until expiry.
        await this.sessionService.addToBlacklist(jti, remainingTime)
      } catch (error) {
        // Ignore errors if token is invalid, as the goal is to log out anyway.
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
