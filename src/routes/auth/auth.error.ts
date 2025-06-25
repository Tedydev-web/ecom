import { GlobalError } from 'src/shared/global.error'

// OTP related errors
export const InvalidOTPException = GlobalError.UnprocessableEntity('auth.error.INVALID_OTP', [
  {
    path: 'code',
  },
])

export const OTPExpiredException = GlobalError.UnprocessableEntity('auth.error.OTP_EXPIRED', [
  {
    path: 'code',
  },
])

export const FailedToSendOTPException = GlobalError.UnprocessableEntity('auth.error.FAILED_TO_SEND_OTP', [
  {
    path: 'code',
  },
])

// Email related errors
export const EmailAlreadyExistsException = GlobalError.UnprocessableEntity('auth.error.EMAIL_ALREADY_EXISTS', [
  {
    path: 'email',
  },
])

export const EmailNotFoundException = GlobalError.UnprocessableEntity('auth.error.EMAIL_NOT_FOUND', [
  {
    path: 'email',
  },
])

// Password related errors
export const InvalidPasswordException = GlobalError.UnprocessableEntity('auth.error.INVALID_PASSWORD', [
  {
    path: 'password',
  },
])

// Auth token related errors
export const RefreshTokenAlreadyUsedException = GlobalError.Unauthorized('auth.error.REFRESH_TOKEN_ALREADY_USED')
export const UnauthorizedAccessException = GlobalError.Unauthorized('auth.error.UNAUTHORIZED_ACCESS')

// Google auth related errors
export const GoogleUserInfoError = GlobalError.InternalServerError('auth.error.FAILED_TO_GET_GOOGLE_USER_INFO')

export const InvalidTOTPException = GlobalError.UnprocessableEntity('auth.error.INVALID_TOTP', [
  {
    path: 'totpCode',
  },
])

export const TOTPAlreadyEnabledException = GlobalError.UnprocessableEntity('auth.error.TOTP_ALREADY_ENABLED', [
  {
    path: 'totpCode',
  },
])

export const TOTPNotEnabledException = GlobalError.UnprocessableEntity('auth.error.TOTP_NOT_ENABLED', [
  {
    path: 'totpCode',
  },
])

export const InvalidTOTPAndCodeException = GlobalError.UnprocessableEntity('auth.error.INVALID_TOTP_AND_CODE', [
  {
    path: 'totpCode',
  },
  {
    path: 'code',
  },
])
