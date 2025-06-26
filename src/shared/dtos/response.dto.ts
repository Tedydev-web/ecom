import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import {
  MessageResSchema,
  SuccessResponseSchema,
  PaginatedResponseSchema,
  ErrorResponseSchema,
  createTypedSuccessResponseSchema,
  createTypedPaginatedResponseSchema,
} from 'src/shared/models/response.model'

// Base DTOs
export class MessageResDTO extends createZodDto(MessageResSchema) {}
export class SuccessResponseDTO extends createZodDto(SuccessResponseSchema) {}
export class PaginatedResponseDTO extends createZodDto(PaginatedResponseSchema) {}
export class ErrorResponseDTO extends createZodDto(ErrorResponseSchema) {}

// Helper function to create typed DTOs - simplified version
export function createTypedSuccessResponseDTO<T extends z.ZodType>(dataSchema: T) {
  const typedSchema = z.object({
    success: z.literal(true),
    statusCode: z.number().int().positive(),
    message: z.string(),
    data: dataSchema,
    metadata: z.record(z.any()).optional(),
    timestamp: z.string(),
    path: z.string(),
    requestId: z.string().optional(),
  })

  return createZodDto(typedSchema)
}

export function createTypedPaginatedResponseDTO<T extends z.ZodType>(itemSchema: T) {
  const paginatedSchema = z.object({
    success: z.literal(true),
    statusCode: z.number().int().positive(),
    message: z.string(),
    data: z.array(itemSchema),
    metadata: z.object({
      totalItems: z.number().int().nonnegative(),
      page: z.number().int().positive(),
      limit: z.number().int().positive(),
      totalPages: z.number().int().nonnegative(),
      hasNext: z.boolean(),
      hasPrev: z.boolean(),
    }),
    timestamp: z.string(),
    path: z.string(),
    requestId: z.string().optional(),
  })

  return createZodDto(paginatedSchema)
}
