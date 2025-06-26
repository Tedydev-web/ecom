import { Body, Controller, Get, HttpCode, HttpStatus, Post, Query, Res, UseGuards } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Response } from 'express'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  DisableTwoFactorBodyDTO,
  ForgotPasswordBodyDTO,
  GetAuthorizationUrlResDTO,
  LoginBodyDTO,
  RegisterBodyDTO,
  SendOTPBodyDTO,
  TwoFactorSetupResDTO,
} from 'src/routes/auth/auth.dto'
import { AuthService } from 'src/routes/auth/auth.service'
import { GoogleService } from 'src/routes/auth/google.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { MessageResDTO, createTypedSuccessResponseDTO } from 'src/shared/dtos/response.dto'
import { Ip } from 'src/shared/decorators/ip.decorator'
import { AccessTokenGuard } from 'src/shared/guards/access-token.guard'

// Create typed response DTOs for endpoints that return data
const TwoFactorSetupResponseDTO = createTypedSuccessResponseDTO(TwoFactorSetupResDTO.schema)

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly googleService: GoogleService,
    private readonly configService: ConfigService,
  ) {}

  @IsPublic()
  @Get('csrf')
  @HttpCode(HttpStatus.OK)
  getCsrfToken() {
    return { message: 'auth.success.CSRF_TOKEN_SUCCESS' }
  }

  @Post('register')
  @IsPublic()
  @ZodSerializerDto(MessageResDTO)
  register(@Body() body: RegisterBodyDTO) {
    return this.authService.register(body)
  }

  @Post('send-otp')
  @IsPublic()
  @ZodSerializerDto(MessageResDTO)
  sendOTP(@Body() body: SendOTPBodyDTO) {
    return this.authService.sendOTP(body)
  }

  @Post('login')
  @IsPublic()
  @ZodSerializerDto(MessageResDTO)
  login(
    @Body() body: LoginBodyDTO,
    @UserAgent() userAgent: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.login(
      {
        ...body,
        userAgent,
        ip,
      },
      res,
    )
  }

  @Post('logout')
  @IsPublic()
  @ZodSerializerDto(MessageResDTO)
  logout(
    @Body() body: any, // RefreshTokenBodyDTO is empty, so we use any
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = res.req.cookies?.refreshToken
    return this.authService.logout(refreshToken, res)
  }

  @Post('refresh-token')
  @IsPublic()
  @ZodSerializerDto(MessageResDTO)
  refreshToken(@Res({ passthrough: true }) res: Response) {
    const request = res.req as any
    const refreshToken = request.cookies?.refreshToken
    const userAgent = request.get('User-Agent') || ''
    const ip = request.ip || ''

    return this.authService.refreshToken({
      refreshToken,
      userAgent,
      ip,
      res,
    })
  }

  @Get('google-link')
  @IsPublic()
  @ZodSerializerDto(GetAuthorizationUrlResDTO)
  getAuthorizationUrl(@UserAgent() userAgent: string, @Ip() ip: string) {
    return this.googleService.getAuthorizationUrl({
      userAgent,
      ip,
    })
  }

  @Get('google/callback')
  @IsPublic()
  async googleCallback(@Query('code') code: string, @Query('state') state: string, @Res() res: Response) {
    const clientUrl = this.configService.get<string>('app.clientUrl')!
    try {
      await this.googleService.googleCallback(
        {
          code,
          state,
        },
        res,
      )
      return res.redirect(clientUrl)
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : 'Đã xảy ra lỗi khi đăng nhập bằng Google, vui lòng thử lại bằng cách khác'
      // URL encode the error message to handle special characters
      const encodedMessage = encodeURIComponent(message)
      return res.redirect(`${clientUrl}/login?error=${encodedMessage}`)
    }
  }

  @Post('forgot-password')
  @IsPublic()
  @ZodSerializerDto(MessageResDTO)
  forgotPassword(@Body() body: ForgotPasswordBodyDTO) {
    return this.authService.forgotPassword(body)
  }

  @Post('setup-2fa')
  @UseGuards(AccessTokenGuard)
  @ZodSerializerDto(TwoFactorSetupResponseDTO)
  setupTwoFactorAuth(@ActiveUser('userId') userId: number) {
    return this.authService.setupTwoFactorAuth(userId)
  }

  @Post('disable-2fa')
  @UseGuards(AccessTokenGuard)
  @ZodSerializerDto(MessageResDTO)
  disableTwoFactorAuth(@Body() body: DisableTwoFactorBodyDTO, @ActiveUser('userId') userId: number) {
    return this.authService.disableTwoFactorAuth({ ...body, userId })
  }
}
