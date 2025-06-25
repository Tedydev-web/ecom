import { GlobalError } from 'src/shared/global.error'

export const InvalidCsrfTokenException = GlobalError.Forbidden('auth.error.INVALID_CSRF_TOKEN')
