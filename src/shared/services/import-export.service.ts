import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import * as ExcelJS from 'exceljs'
import * as fs from 'fs'
import * as path from 'path'
import { ImportQueryType, ExportQueryType } from '../models/import-export.model'
import {
  ImportResultType,
  ExportResultType,
  TemplateDefinitionType,
  FieldDefinitionType,
} from '../models/import-export.model'
import { PrismaService } from './prisma.service'

export interface ImportExportConfig {
  tempDir: string
  maxFileSize: number
  allowedMimeTypes: string[]
  defaultBatchSize: number
  maxConcurrentTasks: number
}

@Injectable()
export class ImportExportService {
  private readonly logger = new Logger(ImportExportService.name)
  private readonly config: ImportExportConfig

  constructor(
    private readonly prismaService: PrismaService,
    private readonly configService: ConfigService,
  ) {
    this.config = {
      tempDir: path.join(process.cwd(), 'temp'),
      maxFileSize: 10 * 1024 * 1024, // 10MB
      allowedMimeTypes: [
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-excel',
        'text/csv',
      ],
      defaultBatchSize: 100,
      maxConcurrentTasks: 5,
    }
    this.ensureTempDir()
  }

  // === TEMPLATE GENERATION ===
  async generateTemplate(definition: TemplateDefinitionType): Promise<Buffer> {
    const workbook = new ExcelJS.Workbook()
    const worksheet = workbook.addWorksheet(definition.sheetName)

    // Set up columns
    const columns = this.setupTemplateColumns(definition, worksheet)
    worksheet.columns = columns

    // Add relationship data dropdowns
    if (definition.relationshipFields?.length) {
      await this.addRelationshipDropdowns(definition, workbook, worksheet)
    }

    // Add instructions sheet
    if (definition.instructions?.length) {
      this.addInstructionsSheet(workbook, definition.instructions)
    }

    // Style the template
    this.styleTemplate(worksheet, definition.fields)

    return (await workbook.xlsx.writeBuffer()) as Buffer
  }

  private setupTemplateColumns(definition: TemplateDefinitionType, worksheet: ExcelJS.Worksheet) {
    const columns: any[] = []

    // Regular fields
    for (const field of definition.fields) {
      columns.push({
        header: field.header,
        key: field.key,
        width: field.width || this.getDefaultWidth(field.type),
        style: this.getFieldStyle(field),
      })
    }

    // Relationship fields
    if (definition.relationshipFields) {
      for (const relField of definition.relationshipFields) {
        columns.push({
          header: relField.header,
          key: relField.key,
          width: 20,
          style: { font: { color: { argb: 'FF0066CC' } } },
        })
      }
    }

    return columns
  }

  private async addRelationshipDropdowns(
    definition: TemplateDefinitionType,
    workbook: ExcelJS.Workbook,
    worksheet: ExcelJS.Worksheet,
  ) {
    if (!definition.relationshipFields) return

    for (const relField of definition.relationshipFields) {
      // Query database for dropdown values
      const values = await this.getRelationshipValues(relField)

      if (values.length > 0) {
        // Add hidden sheet với data
        const dataSheet = workbook.addWorksheet(`${relField.key}_data`)
        dataSheet.state = 'hidden'

        values.forEach((value, index) => {
          dataSheet.getCell(index + 1, 1).value = value.display
          dataSheet.getCell(index + 1, 2).value = value.value
        })

        // Add data validation
        const columnIndex = definition.fields.length + definition.relationshipFields.indexOf(relField) + 1
        worksheet.getColumn(columnIndex).eachCell((cell, rowNumber) => {
          if (rowNumber > 1) {
            // Skip header
            cell.dataValidation = {
              type: 'list',
              allowBlank: true,
              formulae: [`${dataSheet.name}!$A$1:$A$${values.length}`],
            }
          }
        })
      }
    }
  }

  private async getRelationshipValues(relField: any): Promise<Array<{ display: string; value: any }>> {
    try {
      // Sử dụng Prisma dynamic model access đúng cách
      const model = (this.prismaService as any)[relField.sourceTable]
      if (!model || typeof model.findMany !== 'function') {
        this.logger.warn(`Model '${relField.sourceTable}' not found or doesn't have findMany method`)
        return []
      }

      const records = await model.findMany({
        where: relField.query || {},
        select: {
          [relField.valueField]: true,
          [relField.displayField]: true,
        },
      })

      return records.map((record: any) => ({
        display: record[relField.displayField],
        value: record[relField.valueField],
      }))
    } catch (error) {
      this.logger.warn(`Failed to load relationship data for ${relField.key}:`, error)
      return []
    }
  }

  private addInstructionsSheet(workbook: ExcelJS.Workbook, instructions: string[]) {
    const instructionSheet = workbook.addWorksheet('Hướng dẫn')
    instructionSheet.getColumn(1).width = 80

    instructions.forEach((instruction, index) => {
      const cell = instructionSheet.getCell(index + 1, 1)
      cell.value = instruction
      cell.style = {
        font: { size: 12 },
        alignment: { wrapText: true, vertical: 'top' },
      }
    })
  }

  private styleTemplate(worksheet: ExcelJS.Worksheet, fields: FieldDefinitionType[]) {
    // Header row styling
    const headerRow = worksheet.getRow(1)
    headerRow.font = { bold: true, color: { argb: 'FFFFFFFF' } }
    headerRow.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FF4472C4' },
    }
    headerRow.height = 25

    // Add sample data row
    const sampleRow = worksheet.getRow(2)
    fields.forEach((field, index) => {
      const cell = sampleRow.getCell(index + 1)
      cell.value = field.example || this.getExampleValue(field.type)
      cell.style = {
        font: { italic: true, color: { argb: 'FF808080' } },
      }
    })

    // Freeze header row
    worksheet.views = [{ state: 'frozen', ySplit: 1 }]
  }

  // === IMPORT PROCESSING ===
  async processImport<T>(
    buffer: Buffer,
    query: ImportQueryType,
    validator: (data: any[]) => Promise<{ valid: any[]; errors: any[] }>,
    processor: (validData: any[]) => Promise<T[]>,
  ): Promise<ImportResultType> {
    const startTime = Date.now()
    this.logger.log(`Starting import process with ${query.batchSize} batch size`)

    try {
      // Parse Excel file
      const rawData = await this.parseExcelFile(buffer)

      if (rawData.length === 0) {
        return {
          totalRecords: 0,
          successCount: 0,
          errorCount: 0,
          skippedCount: 0,
          errors: [{ row: 1, message: 'File không chứa dữ liệu hợp lệ' }],
        }
      }

      // Validate data
      const { valid: validData, errors: validationErrors } = await validator(rawData)

      if (query.validateOnly) {
        return {
          totalRecords: rawData.length,
          successCount: validData.length,
          errorCount: validationErrors.length,
          skippedCount: 0,
          errors: validationErrors,
        }
      }

      // Process in batches
      const results = await this.processBatches(validData, query, processor)

      const processingTime = Date.now() - startTime
      this.logger.log(`Import completed in ${processingTime}ms`)

      return {
        totalRecords: rawData.length,
        successCount: results.successCount,
        errorCount: validationErrors.length + results.errorCount,
        skippedCount: results.skippedCount,
        errors: [...validationErrors, ...results.errors],
        warnings: results.warnings,
        summary: {
          processingTimeMs: processingTime,
          batchSize: query.batchSize,
        },
      }
    } catch (error) {
      this.logger.error('Import failed:', error)
      throw error
    }
  }

  private async parseExcelFile(buffer: Buffer): Promise<any[]> {
    const workbook = new ExcelJS.Workbook()
    await workbook.xlsx.load(buffer)

    const worksheet = workbook.getWorksheet(1)
    if (!worksheet) throw new Error('Worksheet không tồn tại')

    const data: any[] = []
    const headers: string[] = []

    // Get headers from first row
    const headerRow = worksheet.getRow(1)
    headerRow.eachCell((cell, colNumber) => {
      headers[colNumber] = cell.value?.toString() || `column_${colNumber}`
    })

    // Process data rows
    worksheet.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return // Skip header

      const rowData: any = { __rowNumber: rowNumber }
      row.eachCell((cell, colNumber) => {
        const header = headers[colNumber]
        if (header) {
          rowData[header] = this.parseCellValue(cell.value)
        }
      })

      // Only add rows with at least one non-empty value
      if (Object.values(rowData).some((value) => value !== null && value !== undefined && value !== '')) {
        data.push(rowData)
      }
    })

    return data
  }

  private async processBatches<T>(
    data: any[],
    query: ImportQueryType,
    processor: (batch: any[]) => Promise<T[]>,
  ): Promise<{
    successCount: number
    errorCount: number
    skippedCount: number
    errors: any[]
    warnings: any[]
  }> {
    const batchSize = query.batchSize || this.config.defaultBatchSize
    const batches = this.chunkArray(data, batchSize)

    let successCount = 0
    let errorCount = 0
    const skippedCount = 0 // Make const since never reassigned
    const errors: any[] = []
    const warnings: any[] = []

    // Process batches concurrently but limited
    const promises = batches.map(async (batch, batchIndex) => {
      try {
        this.logger.log(`Processing batch ${batchIndex + 1}/${batches.length}`)

        const results = await processor(batch)
        return {
          success: results.length,
          errors: [],
          batchIndex,
        }
      } catch (error) {
        this.logger.error(`Batch ${batchIndex + 1} failed:`, error)

        if (query.skipErrors) {
          return {
            success: 0,
            errors: batch.map((item, index) => ({
              row: item.__rowNumber || batchIndex * batchSize + index + 2,
              message: String(error) || 'Lỗi xử lý batch',
              value: item,
            })),
            batchIndex,
          }
        } else {
          throw error
        }
      }
    })

    // Execute with concurrency limit
    const batchResults = await this.executeConcurrently(promises, this.config.maxConcurrentTasks)

    batchResults.forEach((result) => {
      successCount += result.success
      errorCount += result.errors.length
      errors.push(...result.errors)
    })

    return { successCount, errorCount, skippedCount, errors, warnings }
  }

  // === EXPORT PROCESSING ===
  async processExport<T>(
    data: T[],
    query: ExportQueryType,
    fieldMappings: Record<string, string>,
    formatters?: Record<string, (value: any) => string>,
  ): Promise<{ buffer: Buffer; result: ExportResultType }> {
    const startTime = Date.now()

    if (query.format === 'excel') {
      const { buffer, totalSheets } = await this.exportToExcel(data, query, fieldMappings, formatters)

      return {
        buffer,
        result: {
          filename: `export_${Date.now()}.xlsx`,
          totalRecords: data.length,
          totalSheets,
          fileSize: buffer.length,
        },
      }
    } else if (query.format === 'pdf') {
      // PDF export logic would go here
      throw new Error('PDF export not implemented yet')
    }

    throw new Error(`Unsupported export format: ${query.format as string}`)
  }

  private async exportToExcel<T>(
    data: T[],
    query: ExportQueryType,
    fieldMappings: Record<string, string>,
    formatters?: Record<string, (value: any) => string>,
  ): Promise<{ buffer: Buffer; totalSheets: number }> {
    const workbook = new ExcelJS.Workbook()
    const batchSize = query.batchSize || 1000
    const batches = this.chunkArray(data, batchSize)

    let sheetIndex = 1
    for (const batch of batches) {
      const sheetName = query.sheetName || `Sheet${sheetIndex}`
      const worksheet = workbook.addWorksheet(sheetName)

      // Setup columns
      const columns = Object.entries(fieldMappings).map(([key, header]) => ({
        header,
        key,
        width: 15,
      }))
      worksheet.columns = columns

      // Add data
      batch.forEach((item) => {
        const row: any = {}
        Object.keys(fieldMappings).forEach((key) => {
          const value = this.getNestedValue(item, key)
          row[key] = formatters?.[key] ? formatters[key](value) : value
        })
        worksheet.addRow(row)
      })

      // Style header
      const headerRow = worksheet.getRow(1)
      headerRow.font = { bold: true }
      headerRow.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFE6E6FA' },
      }

      sheetIndex++
    }

    const buffer = (await workbook.xlsx.writeBuffer()) as Buffer
    return { buffer, totalSheets: batches.length }
  }

  // === UTILITY METHODS ===
  private ensureTempDir() {
    if (!fs.existsSync(this.config.tempDir)) {
      fs.mkdirSync(this.config.tempDir, { recursive: true })
    }
  }

  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = []
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size))
    }
    return chunks
  }

  private async executeConcurrently<T>(promises: Promise<T>[], limit: number): Promise<T[]> {
    const results: T[] = []
    for (let i = 0; i < promises.length; i += limit) {
      const batch = promises.slice(i, i + limit)
      const batchResults = await Promise.all(batch)
      results.push(...batchResults)
    }
    return results
  }

  private parseCellValue(value: any): any {
    if (value === null || value === undefined) return null
    if (typeof value === 'string') return value.trim()
    if (value instanceof Date) return value.toISOString()
    return value
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current?.[key], obj)
  }

  private getDefaultWidth(type: string): number {
    switch (type) {
      case 'number':
        return 12
      case 'date':
        return 15
      case 'boolean':
        return 10
      default:
        return 20
    }
  }

  private getFieldStyle(field: FieldDefinitionType): any {
    const style: any = {}

    if (field.required) {
      style.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFFFEEEE' },
      }
    }

    return style
  }

  private getExampleValue(type: string): string {
    switch (type) {
      case 'string':
        return 'Ví dụ text'
      case 'number':
        return '123'
      case 'boolean':
        return 'true'
      case 'date':
        return '2024-01-01'
      case 'enum':
        return 'option1'
      default:
        return 'example'
    }
  }
}
