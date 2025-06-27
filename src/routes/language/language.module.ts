import { Module } from '@nestjs/common'
import { LanguageController } from './language.controller'
import { LanguageService } from './language.service'
import { LanguageRepo } from './language.repo'
import { ImportExportService } from '../../shared/services/import-export.service'

@Module({
  controllers: [LanguageController],
  providers: [LanguageService, LanguageRepo, ImportExportService],
  exports: [LanguageService, LanguageRepo],
})
export class LanguageModule {}
