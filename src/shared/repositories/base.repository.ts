import { Logger } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import { PaginatedResponseType, BasePaginationQueryType } from 'src/shared/dtos/pagination.dto'
import { PrismaService } from '../services/prisma.service'

// Xác định kiểu cho Prisma Transaction Client để có thể sử dụng trong các giao dịch
export type PrismaTransactionClient = Omit<
  Prisma.TransactionClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

// Search options for performance optimization
export interface SearchOptions {
  useFullTextSearch?: boolean
  searchableFields?: string[]
  relationSearches?: Record<string, string[]>
}

export abstract class BaseRepository<T> {
  protected readonly logger: Logger
  private readonly modelName: string

  constructor(
    protected readonly prismaService: PrismaService,
    modelName: string,
  ) {
    this.logger = new Logger(this.constructor.name)
    this.modelName = modelName
  }

  // Cung cấp một phương thức để lấy client, hỗ trợ cả transaction
  protected getClient(prismaClient?: PrismaTransactionClient): PrismaTransactionClient | PrismaService {
    return prismaClient || this.prismaService
  }

  // --- Các phương thức CRUD cơ bản ---

  async findById(id: number, prismaClient?: PrismaTransactionClient): Promise<T | null> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].findUnique({ where: { id } })
  }

  async create(data: any, prismaClient?: PrismaTransactionClient): Promise<T> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].create({ data })
  }

  async update(id: number, data: any, prismaClient?: PrismaTransactionClient): Promise<T> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].update({ where: { id }, data })
  }

  async delete(id: number, prismaClient?: PrismaTransactionClient): Promise<T> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].delete({ where: { id } })
  }

  // --- Standard Offset-based Pagination (Primary & Only) ---
  // Best for: Admin panels, reports, web applications, standard CRUD operations
  protected async paginate(
    query: BasePaginationQueryType,
    where: any = {},
    include: any = {},
    prismaClient?: PrismaTransactionClient,
    searchOptions?: SearchOptions,
  ): Promise<PaginatedResponseType<T>> {
    const client = this.getClient(prismaClient)
    const { page, limit, sortBy, sortOrder, search } = query

    const searchQuery = search ? this.buildSearchQuery(search, searchOptions) : {}
    const finalWhere = { ...where, ...searchQuery }

    const orderBy = this.buildOrderBy(sortBy, sortOrder)

    const findManyArgs = {
      where: finalWhere,
      include,
      skip: (page - 1) * limit,
      take: limit,
      orderBy,
    }

    const countArgs = { where: finalWhere }

    let items: T[]
    let totalItems: number

    if (prismaClient) {
      // Trong transaction, thực hiện song song mà không tạo transaction mới
      ;[items, totalItems] = await Promise.all([
        client[this.modelName].findMany(findManyArgs),
        client[this.modelName].count(countArgs),
      ])
    } else {
      // Sử dụng $transaction để đảm bảo tính nhất quán
      ;[items, totalItems] = await this.prismaService.$transaction([
        this.prismaService[this.modelName].findMany(findManyArgs),
        this.prismaService[this.modelName].count(countArgs),
      ])
    }

    const totalPages = Math.ceil(totalItems / limit)

    return {
      data: items,
      metadata: {
        totalItems,
        page,
        limit,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1,
      },
    }
  }

  // --- Helper Methods ---
  private buildSearchQuery(search: string, options?: SearchOptions): any {
    const searchableFields = options?.searchableFields || this.getSearchableFields()

    if (searchableFields.length === 0) {
      return {}
    }

    // Full-text search cho PostgreSQL/MySQL
    if (options?.useFullTextSearch) {
      return this.buildFullTextSearchQuery(search, searchableFields)
    }

    // Standard ILIKE search
    return {
      OR: searchableFields.map((field) => ({
        [field]: {
          contains: search,
          mode: 'insensitive',
        },
      })),
    }
  }

  private buildFullTextSearchQuery(search: string, fields: string[]): any {
    // Implementation cho full-text search
    // Có thể customize theo database engine
    return {
      OR: fields.map((field) => ({
        [field]: {
          search: search,
        },
      })),
    }
  }

  private buildOrderBy(sortBy?: string, sortOrder?: string): any {
    if (!sortBy) {
      return { id: 'desc' } // Default sort
    }

    return { [sortBy]: sortOrder || 'desc' }
  }

  /**
   * Các repository con phải implement phương thức này để xác định các trường có thể tìm kiếm.
   */
  protected abstract getSearchableFields(): string[]

  // --- Performance Optimization Methods ---
  protected async getEstimatedCount(where: any = {}): Promise<number> {
    // Sử dụng EXPLAIN ESTIMATE cho large tables thay vì COUNT(*)
    // Implementation tùy thuộc vào database engine
    try {
      return await this.prismaService[this.modelName].count({ where })
    } catch (error) {
      this.logger.warn(`Failed to get count, returning estimate: ${error}`)
      return 0
    }
  }

  protected generateCacheKey(prefix: string, params: any): string {
    const key = Object.keys(params)
      .sort()
      .map((k) => `${k}:${params[k]}`)
      .join('|')
    return `${prefix}:${Buffer.from(key).toString('base64')}`
  }
}
