import { Injectable } from '@nestjs/common'
import { LanguageRepo } from 'src/routes/language/language.repo'
import { CreateLanguageBodyType, UpdateLanguageBodyType, LanguageType } from 'src/routes/language/language.model'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { LanguageError } from 'src/routes/language/language.error'
import { BasePaginationQueryType, PaginatedResponseType } from 'src/shared/dtos/pagination.dto'

@Injectable()
export class LanguageService {
  constructor(private languageRepo: LanguageRepo) {}

  // Standard offset-based pagination for admin/management UI
  async findAll(query: BasePaginationQueryType): Promise<PaginatedResponseType<LanguageType>> {
    try {
      return await this.languageRepo.findAllWithPagination(query)
    } catch (error) {
      throw LanguageError.OperationFailed
    }
  }

  async findById(id: string): Promise<LanguageType> {
    try {
      const language = await this.languageRepo.findById(id)
      if (!language) {
        throw LanguageError.NotFound
      }
      return language
    } catch (error) {
      if (error === LanguageError.NotFound) {
        throw error
      }
      throw LanguageError.OperationFailed
    }
  }

  async create(body: CreateLanguageBodyType, userId: number): Promise<LanguageType> {
    try {
      const language = await this.languageRepo.create({
        data: body,
        createdById: userId,
      })
      return language
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw LanguageError.AlreadyExists
      }
      throw LanguageError.OperationFailed
    }
  }

  async update(id: string, body: UpdateLanguageBodyType, userId: number): Promise<LanguageType> {
    try {
      const language = await this.languageRepo.update(id, { ...body, updatedById: userId })
      return language
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw LanguageError.NotFound
      }
      if (isUniqueConstraintPrismaError(error)) {
        throw LanguageError.AlreadyExists
      }
      throw LanguageError.OperationFailed
    }
  }

  async delete(id: string): Promise<LanguageType> {
    try {
      const language = await this.languageRepo.delete(id)
      return language
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw LanguageError.NotFound
      }
      throw LanguageError.OperationFailed
    }
  }
}
