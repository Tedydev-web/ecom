import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

export const BasePaginationQuerySchema = z.object({
  page: z.coerce.number().int().positive().optional().default(1),
  limit: z.coerce.number().int().positive().max(100).optional().default(10),
  sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  sortBy: z.string().optional(),
  search: z.string().optional(),
})

export type BasePaginationQueryType = z.infer<typeof BasePaginationQuerySchema>
export class BasePaginationQueryDTO extends createZodDto(BasePaginationQuerySchema) {}

export interface PaginationMetadata {
  totalItems: number
  page: number
  limit: number
  totalPages: number
}

export interface PaginatedResponseType<T> {
  data: T[]
  metadata: PaginationMetadata
}
