import { Logger } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import { PaginatedResponseType, BasePaginationQueryType } from 'src/shared/dtos/pagination.dto'
import { PrismaService } from '../services/prisma.service'

// Xác định kiểu cho Prisma Transaction Client để có thể sử dụng trong các giao dịch
export type PrismaTransactionClient = Omit<
  Prisma.TransactionClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

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

  // --- Các phương thức tìm kiếm và phân trang ---

  protected async paginate(
    query: BasePaginationQueryType,
    where: any = {},
    include: any = {},
    prismaClient?: PrismaTransactionClient,
  ): Promise<PaginatedResponseType<T>> {
    const client = this.getClient(prismaClient)
    const { page, limit, sortBy, sortOrder, search } = query

    const searchQuery = search ? this.getSearchQuery(search) : {}
    const finalWhere = { ...where, ...searchQuery }

    const findManyArgs = {
      where: finalWhere,
      include,
      skip: (page - 1) * limit,
      take: limit,
      orderBy: sortBy ? { [sortBy]: sortOrder } : undefined,
    }

    const countArgs = {
      where: finalWhere,
    }

    let items: T[]
    let totalItems: number

    if (prismaClient) {
      // Nếu đang ở trong một transaction, thực hiện các truy vấn song song mà không tạo transaction mới
      ;[items, totalItems] = await Promise.all([
        client[this.modelName].findMany(findManyArgs),
        client[this.modelName].count(countArgs),
      ])
    } else {
      // Nếu không, sử dụng $transaction để đảm bảo tính nguyên tử
      ;[items, totalItems] = await this.prismaService.$transaction([
        this.prismaService[this.modelName].findMany(findManyArgs),
        this.prismaService[this.modelName].count(countArgs),
      ])
    }

    return {
      data: items,
      metadata: {
        totalItems,
        page,
        limit,
        totalPages: Math.ceil(totalItems / limit),
        hasNext: page < Math.ceil(totalItems / limit),
        hasPrev: page > 1,
      },
    }
  }

  /**
   * Các repository con phải implement phương thức này để xác định các trường có thể tìm kiếm.
   */
  protected abstract getSearchableFields(): string[]

  private getSearchQuery(search: string): any {
    const searchableFields = this.getSearchableFields()
    if (searchableFields.length === 0) {
      return {}
    }
    return {
      OR: searchableFields.map((field) => ({
        [field]: {
          contains: search,
          mode: 'insensitive', // Tìm kiếm không phân biệt hoa thường
        },
      })),
    }
  }
}
