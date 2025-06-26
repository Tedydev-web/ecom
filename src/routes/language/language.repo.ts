import { Injectable } from '@nestjs/common'
import { CreateLanguageBodyType, LanguageType, UpdateLanguageBodyType } from 'src/routes/language/language.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { BasePaginationQueryType, PaginatedResponseType } from 'src/shared/dtos/pagination.dto'

@Injectable()
export class LanguageRepo {
  constructor(private prismaService: PrismaService) {}

  async findAllWithPagination(query: BasePaginationQueryType): Promise<PaginatedResponseType<LanguageType>> {
    const { page, limit, sortBy, sortOrder, search } = query

    // Build where clause
    const where: any = {
      deletedAt: null,
    }

    // Add search functionality
    if (search) {
      where.OR = [
        { id: { contains: search, mode: 'insensitive' } },
        { name: { contains: search, mode: 'insensitive' } },
      ]
    }

    // Build orderBy clause
    const orderBy: any = {}
    if (sortBy) {
      orderBy[sortBy] = sortOrder
    } else {
      orderBy.createdAt = 'desc' // Default sort
    }

    // Execute queries in parallel
    const [data, totalItems] = await Promise.all([
      this.prismaService.language.findMany({
        where,
        orderBy,
        skip: (page - 1) * limit,
        take: limit,
      }),
      this.prismaService.language.count({ where }),
    ])

    const totalPages = Math.ceil(totalItems / limit)

    return {
      data,
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

  findAll(): Promise<LanguageType[]> {
    return this.prismaService.language.findMany({
      where: {
        deletedAt: null,
      },
    })
  }

  findById(id: string): Promise<LanguageType | null> {
    return this.prismaService.language.findUnique({
      where: {
        id,
        deletedAt: null,
      },
    })
  }

  create({ createdById, data }: { createdById: number; data: CreateLanguageBodyType }): Promise<LanguageType> {
    return this.prismaService.language.create({
      data: {
        ...data,
        createdById,
      },
    })
  }

  update({
    id,
    updatedById,
    data,
  }: {
    id: string
    updatedById: number
    data: UpdateLanguageBodyType
  }): Promise<LanguageType> {
    return this.prismaService.language.update({
      where: {
        id,
        deletedAt: null,
      },
      data: {
        ...data,
        updatedById,
      },
    })
  }

  delete(id: string, isHard?: boolean): Promise<LanguageType> {
    return isHard
      ? this.prismaService.language.delete({
          where: {
            id,
          },
        })
      : this.prismaService.language.update({
          where: {
            id,
            deletedAt: null,
          },
          data: {
            deletedAt: new Date(),
          },
        })
  }
}
