import { AuthError } from './auth.error'

/**
 * CSRF-specific errors exported from centralized auth errors
 * This maintains consistency and avoids duplication
 */
export const CsrfError = {
  InvalidToken: AuthError.InvalidCsrfToken,
  TokenMissing: AuthError.CsrfTokenMissing,
} as const

export type CsrfErrorKey = keyof typeof CsrfError
