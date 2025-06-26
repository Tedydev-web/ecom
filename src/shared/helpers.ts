import { randomInt } from 'crypto'
import { GlobalError } from './global.error'

// Database Error Type Guards (không cần import trực tiếp từ Prisma)
export function isUniqueConstraintPrismaError(error: any): boolean {
  return error?.code === 'P2002'
}

export function isNotFoundPrismaError(error: any): boolean {
  return error?.code === 'P2025'
}

export const generateOTP = () => {
  return String(randomInt(100000, 1000000))
}

// Entity not found exception helper
export const NotFoundRecordException = (entity: string = 'record') => GlobalError.NotFound(entity)
