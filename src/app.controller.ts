import { Controller, Get } from '@nestjs/common'
import { AppService } from './app.service'
import { IsPublic } from './shared/decorators/auth.decorator'

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @IsPublic()
  @Get('/get-cookies')
  getCookies(): string {
    return this.appService.getCookies()
  }
}
