import { Injectable } from '@nestjs/common'
import { CreateLanguageBodyType, LanguageType } from 'src/routes/language/language.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { BasePaginationQueryType, PaginatedResponseType } from 'src/shared/dtos/pagination.dto'
import { BaseRepository } from 'src/shared/repositories/base.repository'

@Injectable()
export class LanguageRepo extends BaseRepository<LanguageType> {
  constructor(prismaService: PrismaService) {
    super(prismaService, 'language')
  }

  // Các trường cho phép search
  protected getSearchableFields(): string[] {
    return ['id', 'name']
  }

  // Các trường cho phép sort
  protected getSortableFields(): string[] {
    return ['id', 'name', 'createdAt', 'updatedAt']
  }

  async findAllWithPagination(query: BasePaginationQueryType): Promise<PaginatedResponseType<LanguageType>> {
    // Luôn filter deletedAt: null
    return this.paginate(query, { deletedAt: null })
  }

  findAll(): Promise<LanguageType[]> {
    return this.prismaService.language.findMany({ where: { deletedAt: null } })
  }

  create({ createdById, data }: { createdById: number; data: CreateLanguageBodyType }): Promise<LanguageType> {
    return this.prismaService.language.create({ data: { ...data, createdById } })
  }
}
