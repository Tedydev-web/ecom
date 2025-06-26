import { Body, Controller, Delete, Get, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateLanguageBodyDTO,
  GetLanguageDetailResDTO,
  GetLanguageParamsDTO,
  GetLanguagesResDTO,
  UpdateLanguageBodyDTO,
} from 'src/routes/language/language.dto'
import { LanguageService } from 'src/routes/language/language.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResDTO, SuccessResponseDTO } from 'src/shared/dtos/response.dto'
import { BasePaginationQueryDTO } from 'src/shared/dtos/pagination.dto'

@Controller('languages')
export class LanguageController {
  constructor(private readonly languageService: LanguageService) {}

  @Get()
  @ZodSerializerDto(SuccessResponseDTO)
  findAll(@Query() query: BasePaginationQueryDTO) {
    return this.languageService.findAll(query)
  }

  @Get(':languageId')
  @ZodSerializerDto(SuccessResponseDTO)
  findById(@Param() params: GetLanguageParamsDTO) {
    return this.languageService.findById(params.languageId)
  }

  @Post()
  @ZodSerializerDto(SuccessResponseDTO)
  create(@Body() body: CreateLanguageBodyDTO, @ActiveUser('userId') userId: number) {
    return this.languageService.create({
      data: body,
      createdById: userId,
    })
  }

  @Put(':languageId')
  @ZodSerializerDto(SuccessResponseDTO)
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
  @ZodSerializerDto(MessageResDTO)
  delete(@Param() params: GetLanguageParamsDTO) {
    return this.languageService.delete(params.languageId)
  }
}
