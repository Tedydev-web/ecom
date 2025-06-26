import { Module } from '@nestjs/common'
import { AuthService } from 'src/routes/auth/auth.service'
import { AuthController } from 'src/routes/auth/auth.controller'
import { RolesService } from 'src/routes/auth/roles.service'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { GoogleService } from 'src/routes/auth/google.service'
import { SharedModule } from 'src/shared/shared.module'

@Module({
  imports: [SharedModule],
  providers: [AuthService, RolesService, AuthRepository, GoogleService],
  controllers: [AuthController],
})
export class AuthModule {}
