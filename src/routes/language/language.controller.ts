import { Body, Controller, Delete, Get, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateLanguageBodyDTO,
  GetLanguageDetailResDTO,
  GetLanguageParamsDTO,
  GetLanguagesResDTO,
  UpdateLanguageBodyDTO,
  CreateLanguageResDTO,
  UpdateLanguageResDTO,
  DeleteLanguageResDTO,
} from 'src/routes/language/language.dto'
import { LanguageService } from 'src/routes/language/language.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResDTO, SuccessResponseDTO } from 'src/shared/dtos/response.dto'
import { BasePaginationQueryDTO } from 'src/shared/dtos/pagination.dto'
import { AuthType } from 'src/shared/constants/auth.constant'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { LanguageType } from './language.model'

export interface LanguageServiceResponse<T> {
  message: string
  data?: T
  metadata?: any
}

@Controller('languages')
export class LanguageController {
  constructor(private readonly languageService: LanguageService) {}

  @Get()
  @ZodSerializerDto(GetLanguagesResDTO)
  async findAll(@Query() query: BasePaginationQueryDTO): Promise<LanguageServiceResponse<LanguageType[]>> {
    return this.languageService.findAll(query)
  }

  @Get(':languageId')
  @ZodSerializerDto(GetLanguageDetailResDTO)
  findById(@Param() params: GetLanguageParamsDTO) {
    return this.languageService.findById(params.languageId)
  }

  @Post()
  @ZodSerializerDto(CreateLanguageResDTO)
  create(@Body() body: CreateLanguageBodyDTO, @ActiveUser('userId') userId: number) {
    return this.languageService.create({
      data: body,
      createdById: userId,
    })
  }

  @Put(':languageId')
  @ZodSerializerDto(UpdateLanguageResDTO)
  update(
    @Body() body: UpdateLanguageBodyDTO,
    @Param() params: GetLanguageParamsDTO,
    @ActiveUser('userId') userId: number,
  ) {
    return this.languageService.update({
      data: body,
      id: params.languageId,
      updatedById: userId,
    })
  }

  @Delete(':languageId')
  @ZodSerializerDto(DeleteLanguageResDTO)
  delete(@Param() params: GetLanguageParamsDTO) {
    return this.languageService.delete(params.languageId)
  }
}
