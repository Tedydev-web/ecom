import { Injectable } from '@nestjs/common'
import { LanguageRepo } from 'src/routes/language/language.repo'
import { CreateLanguageBodyType, UpdateLanguageBodyType } from 'src/routes/language/language.model'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { LanguageError } from 'src/routes/language/language.error'
import { BasePaginationQueryType } from 'src/shared/dtos/pagination.dto'

@Injectable()
export class LanguageService {
  constructor(private languageRepo: LanguageRepo) {}

  async findAll(query?: BasePaginationQueryType) {
    const data = await this.languageRepo.findAll()

    // Trả về data trực tiếp, để TransformInterceptor xử lý cấu trúc response
    return {
      message: 'language.success.GET_ALL_SUCCESS',
      data,
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
