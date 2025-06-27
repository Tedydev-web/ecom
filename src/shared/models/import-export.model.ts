import { z } from 'zod'

// === QUERY SCHEMAS ===

// Import Query Schema
export const ImportQuerySchema = z.object({
  validateOnly: z.boolean().optional().default(false),
  batchSize: z.coerce.number().int().positive().max(1000).optional().default(100),
  skipErrors: z.boolean().optional().default(false),
  returnDetails: z.boolean().optional().default(true),
})

// Export Query Schema
export const ExportQuerySchema = z.object({
  format: z.enum(['excel', 'pdf']).default('excel'),
  includeHeaders: z.boolean().optional().default(true),
  sheetName: z.string().optional(),
  template: z.boolean().optional().default(false),

  batchSize: z.coerce.number().int().positive().max(5000).optional().default(1000),

  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(10000).default(1000),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
  search: z.string().optional(),

  filters: z.record(z.any()).optional(),
})

// Upload File Schema
export const UploadFileSchema = z.object({
  fieldname: z.string(),
  originalname: z.string(),
  encoding: z.string(),
  mimetype: z
    .string()
    .refine(
      (type) =>
        [
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          'application/vnd.ms-excel',
          'text/csv',
        ].includes(type),
      { message: 'File type not supported. Only Excel (.xlsx, .xls) and CSV files are allowed.' },
    ),
  size: z.number().max(10 * 1024 * 1024, 'File size must not exceed 10MB'),
  buffer: z.instanceof(Buffer),
})

// === FIELD DEFINITION SCHEMAS ===

// Field Definition Schema (for template generation)
export const FieldValidationSchema = z.object({
  min: z.number().optional(),
  max: z.number().optional(),
  maxLength: z.number().optional(), // Thêm maxLength
  pattern: z.string().optional(),
  enum: z.array(z.string()).optional(),
})

export const FieldDefinitionSchema = z.object({
  key: z.string(),
  header: z.string(),
  type: z.enum(['string', 'number', 'boolean', 'date', 'enum']),
  required: z.boolean(),
  width: z.number().optional(),
  example: z.string().optional(),
  description: z.string().optional(),
  validation: FieldValidationSchema.optional(),
})

export const RelationshipFieldSchema = z.object({
  key: z.string(),
  header: z.string(),
  sourceTable: z.string(), // Tên table trong Prisma
  valueField: z.string(), // Field chứa giá trị (thường là id)
  displayField: z.string(), // Field hiển thị (thường là name)
  query: z.record(z.any()).optional(), // Where clause để filter data
})

export const TemplateDefinitionSchema = z.object({
  moduleName: z.string(),
  sheetName: z.string(),
  fields: z.array(FieldDefinitionSchema),
  relationshipFields: z.array(RelationshipFieldSchema).optional(),
  instructions: z.array(z.string()).optional(),
})

// Import Result Schema
export const ImportResultSchema = z.object({
  totalRecords: z.number().int().nonnegative(),
  successCount: z.number().int().nonnegative(),
  errorCount: z.number().int().nonnegative(),
  skippedCount: z.number().int().nonnegative(),
  errors: z
    .array(
      z.object({
        row: z.number().int().positive(),
        field: z.string().optional(),
        message: z.string(),
        value: z.any().optional(),
      }),
    )
    .default([]), // Default empty array thay vì optional
  warnings: z
    .array(
      z.object({
        row: z.number().int().positive(),
        message: z.string(),
        field: z.string().optional(),
      }),
    )
    .optional(),
  summary: z.record(z.any()).optional(),
})

// Export Result Schema
export const ExportResultSchema = z.object({
  filename: z.string(),
  totalRecords: z.number().int().nonnegative(),
  totalSheets: z.number().int().positive().default(1), // Default 1 thay vì optional
  fileSize: z.number().int().nonnegative().optional(),
  downloadUrl: z.string().optional(),
  expiresAt: z.date().optional(),
})

// Types
export type ImportQueryType = z.infer<typeof ImportQuerySchema>
export type ExportQueryType = z.infer<typeof ExportQuerySchema>
export type UploadFileType = z.infer<typeof UploadFileSchema>
export type FieldValidationType = z.infer<typeof FieldValidationSchema>
export type FieldDefinitionType = z.infer<typeof FieldDefinitionSchema>
export type RelationshipFieldType = z.infer<typeof RelationshipFieldSchema>
export type TemplateDefinitionType = z.infer<typeof TemplateDefinitionSchema>
export type ImportResultType = z.infer<typeof ImportResultSchema>
export type ExportResultType = z.infer<typeof ExportResultSchema>

// === UTILITY TYPES ===

export interface SearchOptions {
  fields: string[]
  mode?: 'contains' | 'startsWith' | 'endsWith' | 'equals'
  caseSensitive?: boolean
}

export interface PaginationOptions {
  page: number
  limit: number
  sortBy?: string
  sortOrder?: 'asc' | 'desc'
}

export interface ExportOptions extends PaginationOptions {
  format: 'excel' | 'pdf'
  includeHeaders?: boolean
  sheetName?: string
  batchSize?: number
  filters?: Record<string, any>
}
