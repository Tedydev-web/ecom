import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  Res,
  BadRequestException,
  UploadedFile,
  UseInterceptors,
  StreamableFile,
} from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { LanguageService } from 'src/routes/language/language.service'
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
import { BasePaginationQueryDTO, PaginatedResponseType } from 'src/shared/dtos/pagination.dto'
import { AuthType } from 'src/shared/constants/auth.constant'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { ImportQueryDto, ExportQueryDto } from '../../shared/dtos/import-export.dto'
import { LanguageRepo } from './language.repo'
import { FileInterceptor } from '@nestjs/platform-express'
import { Response } from 'express'

@Controller('languages')
@Auth([AuthType.Bearer])
export class LanguageController {
  constructor(
    private readonly languageService: LanguageService,
    private readonly languageRepo: LanguageRepo,
  ) {}

  @Get()
  @ZodSerializerDto(GetLanguagesResDTO)
  async findAll(@Query() query: BasePaginationQueryDTO) {
    const result = await this.languageService.findAll(query)
    return {
      message: 'language.success.GET_LANGUAGES',
      data: result.data,
      metadata: result.metadata,
    }
  }

  @Get(':languageId')
  @ZodSerializerDto(GetLanguageDetailResDTO)
  async findById(@Param() params: GetLanguageParamsDTO) {
    const language = await this.languageService.findById(params.languageId)
    return {
      message: 'language.success.GET_LANGUAGE_DETAIL',
      data: language,
    }
  }

  @Post()
  @ZodSerializerDto(CreateLanguageResDTO)
  async create(@Body() body: CreateLanguageBodyDTO, @ActiveUser('userId') userId: number) {
    const language = await this.languageService.create(body, userId)
    return {
      message: 'language.success.CREATE_LANGUAGE',
      data: language,
    }
  }

  @Put(':languageId')
  @ZodSerializerDto(UpdateLanguageResDTO)
  async update(
    @Param() params: GetLanguageParamsDTO,
    @Body() body: UpdateLanguageBodyDTO,
    @ActiveUser('userId') userId: number,
  ) {
    const language = await this.languageService.update(params.languageId, body, userId)
    return {
      message: 'language.success.UPDATE_LANGUAGE',
      data: language,
    }
  }

  @Delete(':languageId')
  @ZodSerializerDto(DeleteLanguageResDTO)
  async delete(@Param() params: GetLanguageParamsDTO) {
    const language = await this.languageService.delete(params.languageId)
    return {
      message: 'language.success.DELETE_LANGUAGE',
      data: language,
    }
  }

  // === IMPORT/EXPORT ENDPOINTS ===

  @Post('import/template')
  @Auth([AuthType.Bearer])
  async downloadTemplate(@Res({ passthrough: true }) response: Response): Promise<StreamableFile> {
    const buffer = await this.languageRepo.generateTemplate()

    response.set({
      'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'Content-Disposition': 'attachment; filename="language_template.xlsx"',
    })

    return new StreamableFile(buffer)
  }

  @Post('import')
  @Auth([AuthType.Bearer])
  @UseInterceptors(FileInterceptor('file'))
  async importFromExcel(
    @UploadedFile() file: Express.Multer.File,
    @Query() query: ImportQueryDto,
    @ActiveUser('userId') userId: number,
  ): Promise<{ success: boolean; message: string; data: any }> {
    if (!file || !file.buffer) {
      throw new BadRequestException('File is required')
    }

    // Validate file type và size
    const allowedTypes = [
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-excel',
    ]

    if (!allowedTypes.includes(file.mimetype)) {
      throw new BadRequestException('Only Excel files (.xlsx, .xls) are allowed')
    }

    if (file.size > 10 * 1024 * 1024) {
      // 10MB
      throw new BadRequestException('File size must not exceed 10MB')
    }

    try {
      const result = await this.languageRepo.importFromExcel(file.buffer, query)

      return {
        success: true,
        message: 'Import completed successfully',
        data: {
          ...result,
          errors: result.errors || [], // Ensure errors is always an array
        },
      }
    } catch (error) {
      throw new BadRequestException(`Import failed: ${String(error)}`)
    }
  }

  @Get('export')
  @Auth([AuthType.Bearer])
  async exportToExcel(
    @Query() query: ExportQueryDto,
    @Res({ passthrough: true }) response: Response,
  ): Promise<StreamableFile> {
    try {
      const { buffer, result } = await this.languageRepo.exportToExcel(query)

      response.set({
        'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'Content-Disposition': `attachment; filename="${result.filename}"`,
        'X-Total-Records': result.totalRecords.toString(),
        'X-Total-Sheets': (result.totalSheets || 1).toString(),
      })

      return new StreamableFile(buffer)
    } catch (error) {
      throw new BadRequestException(`Export failed: ${String(error)}`)
    }
  }

  @Get('import/validate')
  @Auth([AuthType.Bearer])
  @UseInterceptors(FileInterceptor('file'))
  async validateImportFile(
    @UploadedFile() file: Express.Multer.File,
  ): Promise<{ success: boolean; message: string; data: any }> {
    if (!file || !file.buffer) {
      throw new BadRequestException('File is required')
    }

    try {
      const result = await this.languageRepo.importFromExcel(file.buffer, {
        validateOnly: true,
        batchSize: 100,
        skipErrors: false,
        returnDetails: true,
      })

      return {
        success: true,
        message: 'Validation completed',
        data: {
          ...result,
          errors: result.errors || [], // Ensure errors is always an array
        },
      }
    } catch (error) {
      throw new BadRequestException(`Validation failed: ${String(error)}`)
    }
  }
}
