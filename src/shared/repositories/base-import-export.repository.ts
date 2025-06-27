import { Logger } from '@nestjs/common'
import { BaseRepository, type PrismaTransactionClient } from './base.repository'
import { PrismaService } from '../services/prisma.service'
import { ImportQueryType, ExportQueryType } from '../models/import-export.model'
import {
  ImportResultType,
  ExportResultType,
  TemplateDefinitionType,
  FieldDefinitionType,
} from '../models/import-export.model'
import { ImportExportService } from '../services/import-export.service'

// Export type để các module khác có thể sử dụng
export type { PrismaTransactionClient }

export abstract class BaseImportExportRepository<T> extends BaseRepository<T> {
  protected readonly logger: Logger

  constructor(
    protected readonly prismaService: PrismaService,
    modelName: string,
    protected readonly importExportService: ImportExportService,
  ) {
    super(prismaService, modelName)
    this.logger = new Logger(this.constructor.name)
  }

  // === ABSTRACT METHODS - Phải implement trong repository con ===

  /**
   * Định nghĩa template cho module (fields, relationships, validation rules)
   */
  abstract getTemplateDefinition(): TemplateDefinitionType

  /**
   * Mapping giữa Excel columns và database fields để export
   */
  abstract getExportFieldMappings(): Record<string, string>

  /**
   * Validate và transform dữ liệu từ Excel thành format database
   * @param data Raw data từ Excel
   * @returns Promise with valid data và errors
   */
  abstract validateImportData(data: any[]): Promise<{ valid: any[]; errors: any[] }>

  /**
   * Batch insert dữ liệu đã validate vào database
   * @param validData Dữ liệu đã validate
   * @param prismaClient Optional transaction client
   * @returns Promise với array inserted records
   */
  abstract batchInsert(validData: any[], prismaClient?: PrismaTransactionClient): Promise<T[]>

  /**
   * Custom formatters cho export (optional)
   * @returns Object với key là field name, value là formatter function
   */
  getExportFormatters(): Record<string, (value: any) => string> {
    return {}
  }

  /**
   * Query điều kiện để export data (optional override)
   */
  getExportQuery(query: ExportQueryType): any {
    const where: any = {}

    if (query.search) {
      const searchableFields = this.getSearchableFields()
      if (searchableFields.length > 0) {
        where.OR = searchableFields.map((field) => ({
          [field]: { contains: query.search, mode: 'insensitive' },
        }))
      }
    }

    return where
  }

  // === CONCRETE METHODS - Có thể override nếu cần custom ===

  /**
   * Tạo và download template Excel cho import
   */
  async generateTemplate(): Promise<Buffer> {
    const definition = this.getTemplateDefinition()
    return await this.importExportService.generateTemplate(definition)
  }

  /**
   * Import dữ liệu từ Excel file
   */
  async importFromExcel(
    buffer: Buffer,
    query: ImportQueryType,
    prismaClient?: PrismaTransactionClient,
  ): Promise<ImportResultType> {
    // Custom validator sử dụng method abstract
    const validator = async (data: any[]) => {
      return await this.validateImportData(data)
    }

    // Custom processor sử dụng method abstract
    const processor = async (validData: any[]) => {
      return await this.batchInsert(validData, prismaClient)
    }

    return await this.importExportService.processImport(buffer, query, validator, processor)
  }

  /**
   * Export dữ liệu ra Excel file
   */
  async exportToExcel(
    query: ExportQueryType,
    prismaClient?: PrismaTransactionClient,
  ): Promise<{ buffer: Buffer; result: ExportResultType }> {
    // Build where condition
    const where = this.getExportQuery(query)

    // Get paginated data using base repository pagination
    const paginatedData = await this.paginate(
      {
        page: query.page,
        limit: query.limit,
        sortBy: query.sortBy,
        sortOrder: query.sortOrder,
        search: query.search,
      },
      where,
      {}, // include
      prismaClient,
    )

    // Get field mappings và formatters
    const fieldMappings = this.getExportFieldMappings()
    const formatters = this.getExportFormatters()

    return await this.importExportService.processExport(paginatedData.data, query, fieldMappings, formatters)
  }

  /**
   * Export template (empty Excel với structure và dropdowns)
   */
  async exportTemplate(): Promise<Buffer> {
    return await this.generateTemplate()
  }

  // === UTILITY METHODS ===

  /**
   * Validate required fields trong import data
   */
  protected validateRequiredFields(data: any, requiredFields: string[]): string[] {
    const errors: string[] = []

    requiredFields.forEach((field) => {
      if (!data[field] || data[field] === '' || data[field] === null) {
        errors.push(`Trường '${field}' là bắt buộc`)
      }
    })

    return errors
  }

  /**
   * Transform date từ Excel format
   */
  protected parseExcelDate(value: any): Date | null {
    if (!value) return null

    if (value instanceof Date) return value

    if (typeof value === 'string') {
      const parsed = new Date(value)
      if (!isNaN(parsed.getTime())) return parsed
    }

    if (typeof value === 'number') {
      // Excel serial date number
      const date = new Date((value - 25569) * 86400 * 1000)
      if (!isNaN(date.getTime())) return date
    }

    return null
  }

  /**
   * Parse số từ Excel
   */
  protected parseExcelNumber(value: any): number | null {
    if (value === null || value === undefined || value === '') return null

    const num = Number(value)
    return isNaN(num) ? null : num
  }

  /**
   * Parse boolean từ Excel
   */
  protected parseExcelBoolean(value: any): boolean {
    if (typeof value === 'boolean') return value
    if (typeof value === 'string') {
      const lower = value.toLowerCase().trim()
      return lower === 'true' || lower === '1' || lower === 'yes' || lower === 'có'
    }
    if (typeof value === 'number') return value === 1
    return false
  }

  /**
   * Tìm relationship ID từ display value
   */
  protected async findRelationshipId(
    sourceTable: string,
    displayField: string,
    displayValue: string,
    valueField: string = 'id',
  ): Promise<any> {
    try {
      const record = await this.prismaService[sourceTable].findFirst({
        where: {
          [displayField]: displayValue,
        },
        select: {
          [valueField]: true,
        },
      })

      return record ? record[valueField] : null
    } catch (error) {
      this.logger.warn(`Failed to find relationship ID for ${sourceTable}.${displayField} = ${displayValue}:`, error)
      return null
    }
  }

  /**
   * Generate unique filename cho export
   */
  protected generateExportFilename(prefix: string, format: 'excel' | 'pdf' = 'excel'): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    const extension = format === 'excel' ? 'xlsx' : 'pdf'
    return `${prefix}_${timestamp}.${extension}`
  }
}
