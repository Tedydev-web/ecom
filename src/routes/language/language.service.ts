import { Injectable } from '@nestjs/common'
import { LanguageRepo } from 'src/routes/language/language.repo'
import { CreateLanguageBodyType, UpdateLanguageBodyType, LanguageType } from 'src/routes/language/language.model'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { LanguageError } from 'src/routes/language/language.error'
import { BasePaginationQueryType, PaginatedResponseType } from 'src/shared/dtos/pagination.dto'

export interface LanguageServiceResponse<T> {
  message: string
  data?: T
  metadata?: any
}

@Injectable()
export class LanguageService {
  constructor(private languageRepo: LanguageRepo) {}

  // Standard offset-based pagination for admin/management UI
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

  async findById(id: string): Promise<LanguageServiceResponse<LanguageType>> {
    try {
      const language = await this.languageRepo.findById(id)
      if (!language) {
        throw LanguageError.NotFound
      }
      return {
        message: 'language.success.GET_LANGUAGE_DETAIL',
        data: language,
      }
    } catch (error) {
      if (error === LanguageError.NotFound) {
        throw error
      }
      throw LanguageError.OperationFailed
    }
  }

  async create(body: CreateLanguageBodyType, userId: number): Promise<LanguageServiceResponse<LanguageType>> {
    try {
      const language = await this.languageRepo.create({
        data: body,
        createdById: userId,
      })
      return {
        message: 'language.success.CREATE_LANGUAGE',
        data: language,
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw LanguageError.AlreadyExists
      }
      throw LanguageError.OperationFailed
    }
  }

  async update(
    id: string,
    body: UpdateLanguageBodyType,
    userId: number,
  ): Promise<LanguageServiceResponse<LanguageType>> {
    try {
      const language = await this.languageRepo.update({
        id,
        data: body,
        updatedById: userId,
      })
      return {
        message: 'language.success.UPDATE_LANGUAGE',
        data: language,
      }
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

  async delete(id: string): Promise<LanguageServiceResponse<LanguageType>> {
    try {
      const language = await this.languageRepo.delete(id, false)
      return {
        message: 'language.success.DELETE_LANGUAGE',
        data: language,
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw LanguageError.NotFound
      }
      throw LanguageError.OperationFailed
    }
  }
}
