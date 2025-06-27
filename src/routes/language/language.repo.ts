import { Injectable } from '@nestjs/common'
import { z } from 'zod'
import {
  BaseImportExportRepository,
  PrismaTransactionClient,
} from 'src/shared/repositories/base-import-export.repository'
import { PrismaService } from 'src/shared/services/prisma.service'
import { ImportExportService } from 'src/shared/services/import-export.service'
import { BasePaginationQueryType, PaginatedResponseType } from 'src/shared/dtos/pagination.dto'
import { ExportQueryType } from 'src/shared/models/import-export.model'
import { TemplateDefinitionType, FieldDefinitionType } from 'src/shared/models/import-export.model'
import { CreateLanguageBodyType, LanguageType } from './language.model'

// Validation schema cho import data
const LanguageImportSchema = z.object({
  id: z.string().min(1).max(10),
  name: z.string().min(1).max(500),
})

type LanguageImportType = z.infer<typeof LanguageImportSchema> & { __rowNumber?: number }

interface ImportErrorType {
  row: number
  message: string
  value: unknown
}

@Injectable()
export class LanguageRepo extends BaseImportExportRepository<LanguageType> {
  constructor(prismaService: PrismaService, importExportService: ImportExportService) {
    super(prismaService, 'language', importExportService)
  }

  // === STANDARD REPOSITORY METHODS ===

  protected getSearchableFields(): string[] {
    return ['id', 'name']
  }

  protected getSortableFields(): string[] {
    return ['id', 'name', 'createdAt', 'updatedAt']
  }

  async findAllWithPagination(query: BasePaginationQueryType): Promise<PaginatedResponseType<LanguageType>> {
    return this.paginate(query)
  }

  findAll(): Promise<LanguageType[]> {
    return this.prismaService.language.findMany()
  }

  create({ createdById, data }: { createdById: number; data: CreateLanguageBodyType }): Promise<LanguageType> {
    return this.prismaService.language.create({
      data: {
        ...data,
        createdById,
        updatedById: createdById,
      },
    })
  }

  // === IMPLEMENT IMPORT/EXPORT ABSTRACT METHODS ===

  getTemplateDefinition(): TemplateDefinitionType {
    const fields: FieldDefinitionType[] = [
      {
        key: 'id',
        header: 'Mã Ngôn Ngữ',
        type: 'string',
        required: true,
        width: 15,
        example: 'vi',
        description: 'Mã ngôn ngữ (tối đa 10 ký tự)',
        validation: {
          max: 10,
          pattern: '^[a-z]{2,10}$',
        },
      },
      {
        key: 'name',
        header: 'Tên Ngôn Ngữ',
        type: 'string',
        required: true,
        width: 30,
        example: 'Tiếng Việt',
        description: 'Tên đầy đủ của ngôn ngữ (tối đa 500 ký tự)',
        validation: {
          maxLength: 500,
        },
      },
    ]

    return {
      moduleName: 'language',
      sheetName: 'Languages',
      fields,
      instructions: [
        '1. Mã ngôn ngữ phải là duy nhất và theo chuẩn ISO (ví dụ: vi, en, fr)',
        '2. Mã ngôn ngữ chỉ được chứa chữ cái thường, không dấu, 2-10 ký tự',
        '3. Tên ngôn ngữ là bắt buộc và tối đa 500 ký tự',
        '4. Không được để trống các trường bắt buộc',
        '5. Nếu mã ngôn ngữ đã tồn tại, sẽ được ghi đè (update)',
      ],
    }
  }

  getExportFieldMappings(): Record<string, string> {
    return {
      id: 'Mã Ngôn Ngữ',
      name: 'Tên Ngôn Ngữ',
      createdAt: 'Ngày Tạo',
      updatedAt: 'Ngày Cập Nhật',
      createdById: 'Người Tạo',
      updatedById: 'Người Cập Nhật',
    }
  }

  getExportFormatters(): Record<string, (value: unknown) => string> {
    return {
      createdAt: (value: Date) => (value ? new Date(value).toLocaleString('vi-VN') : ''),
      updatedAt: (value: Date) => (value ? new Date(value).toLocaleString('vi-VN') : ''),
      createdById: (value: number) => (value ? `User #${value}` : ''),
      updatedById: (value: number) => (value ? `User #${value}` : ''),
    }
  }

  async validateImportData(data: unknown[]): Promise<{ valid: LanguageImportType[]; errors: ImportErrorType[] }> {
    const valid: LanguageImportType[] = []
    const errors: ImportErrorType[] = []
    const seenIds = new Set<string>()

    for (let i = 0; i < data.length; i++) {
      const item = data[i] as Record<string, unknown>
      const rowNumber = (item.__rowNumber as number) || i + 2 // Excel row number (bắt đầu từ 2)

      try {
        // Validate required fields
        const fieldErrors = this.validateRequiredFields(item, ['id', 'name'])
        if (fieldErrors.length > 0) {
          errors.push({
            row: rowNumber,
            message: fieldErrors.join(', '),
            value: item,
          })
          continue
        }

        // Validate với Zod schema
        const validatedData = LanguageImportSchema.parse({
          id: (item.id as string)?.toString().toLowerCase().trim(),
          name: (item.name as string)?.toString().trim(),
        })

        // Check duplicate trong file
        if (seenIds.has(validatedData.id)) {
          errors.push({
            row: rowNumber,
            message: `Mã ngôn ngữ '${validatedData.id}' bị trùng lặp trong file`,
            value: item,
          })
          continue
        }
        seenIds.add(validatedData.id)

        // Check pattern cho id
        if (!/^[a-z]{2,10}$/.test(validatedData.id)) {
          errors.push({
            row: rowNumber,
            message: `Mã ngôn ngữ '${validatedData.id}' không hợp lệ. Chỉ được chứa 2-10 chữ cái thường`,
            value: item,
          })
          continue
        }

        valid.push({
          ...validatedData,
          __rowNumber: rowNumber,
        })
      } catch (error) {
        const zodError = error as z.ZodError
        const errorMessages =
          zodError.errors?.map((e) => `${e.path.join('.')}: ${e.message}`).join(', ') || String(error)

        errors.push({
          row: rowNumber,
          message: `Dữ liệu không hợp lệ: ${errorMessages}`,
          value: item,
        })
      }
    }

    return { valid, errors }
  }

  async batchInsert(validData: any[], prismaClient?: PrismaTransactionClient): Promise<LanguageType[]> {
    const client = this.getClient(prismaClient)
    const results: LanguageType[] = []
    const defaultUserId = 1 // System user for import operations

    // Sử dụng upsert để handle cả create và update
    for (const item of validData) {
      try {
        const language = await client.language.upsert({
          where: { id: item.id },
          update: {
            name: item.name,
            updatedById: defaultUserId,
          },
          create: {
            id: item.id,
            name: item.name,
            createdById: defaultUserId,
            updatedById: defaultUserId,
          },
        })

        results.push(language)
      } catch (error) {
        this.logger.error(`Failed to upsert language ${item.id}:`, error)
        throw error
      }
    }

    return results
  }

  getExportQuery(query: ExportQueryType): any {
    const where: any = {}

    // Base search
    if (query.search) {
      where.OR = [
        { id: { contains: query.search, mode: 'insensitive' } },
        { name: { contains: query.search, mode: 'insensitive' } },
      ]
    }

    // Custom filters cho language (có thể mở rộng)
    if (query.filters) {
      // Ví dụ: filter theo created date range
      if (query.filters.createdFrom) {
        where.createdAt = {
          ...where.createdAt,
          gte: new Date(query.filters.createdFrom),
        }
      }
      if (query.filters.createdTo) {
        where.createdAt = {
          ...where.createdAt,
          lte: new Date(query.filters.createdTo),
        }
      }
    }

    return where
  }
}
