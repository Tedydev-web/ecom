import { Controller, Get, Post, Put, Delete, Body, Param, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { LanguageService, LanguageServiceResponse } from 'src/routes/language/language.service'
import {
  CreateLanguageBodyDTO,
  UpdateLanguageBodyDTO,
  GetLanguagesResDTO,
  GetLanguageDetailResDTO,
  CreateLanguageResDTO,
  UpdateLanguageResDTO,
  DeleteLanguageResDTO,
  GetLanguageParamsDTO,
} from 'src/routes/language/language.dto'
import { LanguageType } from './language.model'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResDTO, SuccessResponseDTO } from 'src/shared/dtos/response.dto'
import { BasePaginationQueryDTO } from 'src/shared/dtos/pagination.dto'
import { AuthType } from 'src/shared/constants/auth.constant'
import { Auth } from 'src/shared/decorators/auth.decorator'

@Controller('languages')
@Auth([AuthType.Bearer])
export class LanguageController {
  constructor(private readonly languageService: LanguageService) {}

  @Get()
  @ZodSerializerDto(GetLanguagesResDTO)
  findAll(@Query() query: BasePaginationQueryDTO): Promise<LanguageServiceResponse<LanguageType[]>> {
    return this.languageService.findAll(query)
  }

  @Get(':languageId')
  @ZodSerializerDto(GetLanguageDetailResDTO)
  findById(@Param() params: GetLanguageParamsDTO): Promise<LanguageServiceResponse<LanguageType>> {
    return this.languageService.findById(params.languageId)
  }

  @Post()
  @ZodSerializerDto(CreateLanguageResDTO)
  create(
    @Body() body: CreateLanguageBodyDTO,
    @ActiveUser('userId') userId: number,
  ): Promise<LanguageServiceResponse<LanguageType>> {
    return this.languageService.create(body, userId)
  }

  @Put(':languageId')
  @ZodSerializerDto(UpdateLanguageResDTO)
  update(
    @Param() params: GetLanguageParamsDTO,
    @Body() body: UpdateLanguageBodyDTO,
    @ActiveUser('userId') userId: number,
  ): Promise<LanguageServiceResponse<LanguageType>> {
    return this.languageService.update(params.languageId, body, userId)
  }

  @Delete(':languageId')
  @ZodSerializerDto(DeleteLanguageResDTO)
  delete(@Param() params: GetLanguageParamsDTO): Promise<LanguageServiceResponse<LanguageType>> {
    return this.languageService.delete(params.languageId)
  }
}
