import { createZodDto } from 'nestjs-zod'
import { ImportQuerySchema, ExportQuerySchema } from '../models/import-export.model'

// Chỉ chứa DTOs cho input validation
export class ImportQueryDto extends createZodDto(ImportQuerySchema) {}
export class ExportQueryDto extends createZodDto(ExportQuerySchema) {}
