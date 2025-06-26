import { Injectable } from '@nestjs/common'
import { LanguageRepo } from 'src/routes/language/language.repo'
import { CreateLanguageBodyType, UpdateLanguageBodyType, LanguageType } from 'src/routes/language/language.model'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { LanguageError } from 'src/routes/language/language.error'
import { BasePaginationQueryType, PaginatedResponseType } from 'src/shared/dtos/pagination.dto'

interface LanguageServiceResponse<T> {
  message: string
  data?: T
  metadata?: any
}

@Injectable()
export class LanguageService {
  constructor(private languageRepo: LanguageRepo) {}

  async findAll(query: BasePaginationQueryType): Promise<LanguageServiceResponse<LanguageType[]>> {
    try {
      const result = await this.languageRepo.findAllWithPagination(query)

      return {
        message: 'language.success.GET_LANGUAGES',
        data: result.data,
        metadata: result.metadata,
      }
    } catch (error) {
      throw LanguageError.OperationFailed
    }
  }

  async findById(id: string) {
    const language = await this.languageRepo.findById(id)
    if (!language) {
      throw LanguageError.NotFound
    }

    return {
      message: 'language.success.GET_DETAIL_SUCCESS',
      data: language,
    }
  }

  async create({ data, createdById }: { data: CreateLanguageBodyType; createdById: number }) {
    try {
      const language = await this.languageRepo.create({
        createdById,
        data,
      })

      return {
        message: 'language.success.CREATE_SUCCESS',
        data: language,
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw LanguageError.AlreadyExists
      }
      throw LanguageError.OperationFailed
    }
  }

  async update({ id, data, updatedById }: { id: string; data: UpdateLanguageBodyType; updatedById: number }) {
    try {
      const language = await this.languageRepo.update({
        id,
        updatedById,
        data,
      })

      return {
        message: 'language.success.UPDATE_SUCCESS',
        data: language,
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw LanguageError.NotFound
      }
      throw LanguageError.OperationFailed
    }
  }

  async delete(id: string) {
    try {
      // hard delete
      await this.languageRepo.delete(id, true)
      return {
        message: 'language.success.DELETE_SUCCESS',
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw LanguageError.NotFound
      }
      throw LanguageError.OperationFailed
    }
  }
}
