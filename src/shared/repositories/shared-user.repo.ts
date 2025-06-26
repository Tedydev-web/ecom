import { Injectable } from '@nestjs/common'
import { User, UserStatus } from '@prisma/client'
import { BaseRepository } from 'src/shared/repositories/base.repository'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class SharedUserRepository extends BaseRepository<User> {
  constructor(prismaService: PrismaService) {
    super(prismaService, 'user')
  }

  // Ghi đè phương thức này để xác định các trường có thể tìm kiếm cho model User
  protected getSearchableFields(): string[] {
    return ['name', 'email', 'phoneNumber']
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.prismaService.user.findUnique({
      where: { email },
    })
  }

  async findActiveUserByEmail(email: string): Promise<User | null> {
    return this.prismaService.user.findFirst({
      where: {
        email,
        status: UserStatus.ACTIVE,
      },
    })
  }

  // Các phương thức tùy chỉnh khác cho User có thể được thêm vào đây
}
