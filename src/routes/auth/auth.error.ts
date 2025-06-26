import { GlobalError } from 'src/shared/global.error'

export const AuthError = {
  EmailAlreadyExists: GlobalError.BadRequest('auth.error.EMAIL_ALREADY_EXISTS'),
  EmailNotFound: GlobalError.NotFound('user', { message: 'auth.error.EMAIL_NOT_FOUND' }),
  InvalidPassword: GlobalError.Unauthorized('auth.error.INVALID_PASSWORD'),

  // OTP Errors
  InvalidOTP: GlobalError.BadRequest('auth.error.INVALID_OTP'),
  OTPExpired: GlobalError.BadRequest('auth.error.OTP_EXPIRED'),
  FailedToSendOTP: GlobalError.InternalServerError('auth.error.FAILED_TO_SEND_OTP'),

  // 2FA/TOTP Errors
  InvalidTOTP: GlobalError.BadRequest('auth.error.INVALID_TOTP'),
  InvalidTOTPAndCode: GlobalError.BadRequest('auth.error.INVALID_TOTP_AND_CODE'),
  TOTPAlreadyEnabled: GlobalError.BadRequest('auth.error.TOTP_ALREADY_ENABLED'),
  TOTPNotEnabled: GlobalError.BadRequest('auth.error.TOTP_NOT_ENABLED'),
  Disable2FARequiresCode: GlobalError.BadRequest('auth.error.DISABLE_2FA_REQUIRES_CODE'),

  // Token Errors
  RefreshTokenRequired: GlobalError.Unauthorized('auth.error.REFRESH_TOKEN_REQUIRED'),
  InvalidRefreshToken: GlobalError.Unauthorized('auth.error.INVALID_REFRESH_TOKEN'),
  RefreshTokenReused: GlobalError.Forbidden('auth.error.REFRESH_TOKEN_REUSED'),

  // General Auth Errors
  UserNotFound: GlobalError.NotFound('user', { message: 'auth.error.USER_NOT_FOUND' }),
  UserNotActive: GlobalError.Forbidden('auth.error.USER_NOT_ACTIVE'),

  // Google OAuth Errors
  GoogleUserInfoError: GlobalError.InternalServerError('auth.error.GOOGLE_USER_INFO_ERROR'),
  InvalidCsrfToken: GlobalError.Forbidden('auth.error.INVALID_CSRF_TOKEN'),
}
