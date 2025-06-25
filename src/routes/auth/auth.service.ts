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
import {
  EmailAlreadyExistsException,
  EmailNotFoundException,
  FailedToSendOTPException,
  InvalidOTPException,
  InvalidPasswordException,
  InvalidTOTPAndCodeException,
  InvalidTOTPException,
  OTPExpiredException,
  RefreshTokenAlreadyUsedException,
  TOTPAlreadyEnabledException,
  TOTPNotEnabledException,
  UnauthorizedAccessException,
} from 'src/routes/auth/auth.error'
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
      throw InvalidOTPException
    }
    if (vevificationCode.expiresAt < new Date()) {
      throw OTPExpiredException
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
            type: TypeOfVerificationCode.FORGOT_PASSWORD,
          },
        }),
      ])
      return user
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw EmailAlreadyExistsException
      }
      throw error
    }
  }

  async sendOTP(body: SendOTPBodyType) {
    const user = await this.sharedUserRepository.findUnique({
      email: body.email,
    })
    if (body.type === TypeOfVerificationCode.REGISTER && user) {
      throw EmailAlreadyExistsException
    }
    if (body.type === TypeOfVerificationCode.FORGOT_PASSWORD && !user) {
      throw EmailNotFoundException
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
      throw FailedToSendOTPException
    }
    return { message: 'auth.success.OTP_SENT' }
  }

  async login(body: LoginBodyType & { userAgent: string; ip: string }, res: Response) {
    // 1. Lấy thông tin user, kiểm tra user có tồn tại hay không, mật khẩu có đúng không
    const user = await this.authRepository.findUniqueUserIncludeRole({
      email: body.email,
    })

    if (!user) {
      throw EmailNotFoundException
    }

    const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
    if (!isPasswordMatch) {
      throw InvalidPasswordException
    }
    // 2. Nếu user đã bật mã 2FA thì kiểm tra mã 2FA TOTP Code hoặc OTP Code (email)
    if (user.totpSecret) {
      // Nếu không có mã TOTP Code và Code thì thông báo cho client biết
      if (!body.totpCode && !body.code) {
        throw InvalidTOTPAndCodeException
      }

      // Kiểm tra TOTP Code có hợp lệ hay không
      if (body.totpCode) {
        const isValid = this.twoFactorService.verifyTOTP({
          secret: user.totpSecret,
          token: body.totpCode,
        })
        if (!isValid) {
          throw InvalidTOTPException
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
      }),
    ])
    const decodedRefreshToken = await this.tokenService.verifyRefreshToken(refreshToken)
    await this.authRepository.createRefreshToken({
      token: refreshToken,
      userId,
      expiresAt: new Date(decodedRefreshToken.exp * 1000),
      deviceId,
    })
    return { accessToken, refreshToken }
  }

  async refreshToken({ refreshToken, userAgent, ip, res }: RefreshTokenInput) {
    if (!refreshToken) {
      throw GlobalError.Unauthorized('auth.error.REFRESH_TOKEN_REQUIRED')
    }
    const { jti, exp } = await this.tokenService.verifyRefreshToken(refreshToken).catch(() => {
      throw GlobalError.Unauthorized('auth.error.INVALID_REFRESH_TOKEN')
    })

    const isUsed = await this.sessionService.isRefreshTokenUsed(jti)
    if (isUsed) {
      // TODO: Đây là một sự kiện bảo mật nghiêm trọng, cần có hành động mạnh hơn
      // như thu hồi tất cả các phiên của user.
      throw GlobalError.Forbidden('auth.error.REFRESH_TOKEN_REUSED')
    }

    const refreshTokenRecord = await this.authRepository.findUniqueRefreshTokenIncludeUserRole({
      token: refreshToken,
    })

    if (!refreshTokenRecord) {
      this.cookieService.clearTokenCookies(res)
      throw GlobalError.Unauthorized('auth.error.REFRESH_TOKEN_NOT_FOUND_IN_DB')
    }

    if (refreshTokenRecord.user.status !== 'ACTIVE') {
      this.cookieService.clearTokenCookies(res)
      throw GlobalError.Forbidden('auth.error.USER_NOT_ACTIVE')
    }

    // Đánh dấu RT cũ là đã sử dụng
    await this.sessionService.markRefreshTokenAsUsed(jti)

    let device = await this.authRepository.findUniqueDevice({
      id: refreshTokenRecord.deviceId,
    })

    if (!device) {
      device = await this.authRepository.createDevice({
        userId: refreshTokenRecord.user.id,
        userAgent,
        ip,
      })
    } else {
      // Cập nhật lastActive và có thể cả IP nếu cần
      device = await this.authRepository.updateDevice(device.id, {
        lastActive: new Date(),
        ip,
      })
    }

    const tokens = await this.generateTokens({
      userId: refreshTokenRecord.user.id,
      deviceId: device.id,
      roleId: refreshTokenRecord.user.role.id,
      roleName: refreshTokenRecord.user.role.name,
    })
    this.cookieService.setTokenCookies(res, tokens.accessToken, tokens.refreshToken, true) // Refresh token should always extend session
    const { password, totpSecret, ...userWithoutSensitiveData } = refreshTokenRecord.user
    res.status(HttpStatus.OK).send({ message: 'auth.success.REFRESH_TOKEN_SUCCESS' })
    return userWithoutSensitiveData
  }

  async logout(refreshToken: string, res: Response) {
    if (!refreshToken) {
      return { message: 'auth.success.LOGOUT_SUCCESS' }
    }
    try {
      const { jti, exp } = await this.tokenService.verifyRefreshToken(refreshToken)
      const remainingTime = exp - Math.floor(Date.now() / 1000)

      await this.sessionService.addToBlacklist(jti, remainingTime)
      await this.authRepository.deleteRefreshToken({ token: refreshToken })
    } catch (error) {
      // Bỏ qua lỗi nếu token không hợp lệ, vì mục tiêu là đăng xuất
    } finally {
      this.cookieService.clearTokenCookies(res)
    }

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
      throw EmailNotFoundException
    }
    if (user.totpSecret) {
      throw TOTPAlreadyEnabledException
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
      throw EmailNotFoundException
    }
    if (!user.totpSecret) {
      throw TOTPNotEnabledException
    }

    // 2. Kiểm tra mã TOTP có hợp lệ hay không
    if (totpCode) {
      const isValid = this.twoFactorService.verifyTOTP({
        secret: user.totpSecret,
        token: totpCode,
      })
      if (!isValid) {
        throw InvalidTOTPException
      }
    } else if (code) {
      // 3. Kiểm tra mã OTP email có hợp lệ hay không
      await this.validateVerificationCode({
        email: user.email,
        code,
        type: TypeOfVerificationCode.DISABLE_2FA,
      })
    }

    // 4. Cập nhật secret thành null
    await this.authRepository.updateUser({ id: userId }, { totpSecret: null })

    // 5. Trả về thông báo
    return {
      message: 'auth.success.DISABLE_2FA_SUCCESS',
    }
  }
}
