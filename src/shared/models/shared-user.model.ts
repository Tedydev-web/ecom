import { UserStatus } from 'src/shared/constants/auth.constant'
import { z } from 'zod'

export const RoleSchema = z.object({
  id: z.number().positive(),
  name: z.string().min(1).max(50),
  description: z.string().nullable(),
  permissions: z.array(z.any()).optional(), // Sẽ được định nghĩa rõ hơn sau
  createdAt: z.date(),
  updatedAt: z.date(),
})

export const UserSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  name: z.string().min(1).max(100),
  password: z.string().min(6).max(100),
  phoneNumber: z.string().min(9).max(15),
  avatar: z.string().nullable(),
  totpSecret: z.string().nullable(),
  status: z.enum([UserStatus.ACTIVE, UserStatus.INACTIVE, UserStatus.BLOCKED]),
  roleId: z.number().positive(),
  role: RoleSchema.optional(),
  createdById: z.number().nullable(),
  updatedById: z.number().nullable(),
  deletedById: z.number().nullable(),
  revokedAllSessionsBefore: z.date().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date(),
})

export type UserType = z.infer<typeof UserSchema>
export type RoleType = z.infer<typeof RoleSchema>
