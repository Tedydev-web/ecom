import { Injectable } from '@nestjs/common'
import { RoleName } from 'src/shared/constants/role.constant'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Role } from '@prisma/client'

@Injectable()
export class RolesService {
  private clientRoleId: number | null = null
  private rolesCache: Map<number, Role> = new Map()

  constructor(private readonly prismaService: PrismaService) {}

  async getClientRoleId(): Promise<number> {
    if (this.clientRoleId !== null) {
      return this.clientRoleId
    }
    const role = await this.prismaService.role.findFirst({
      where: {
        name: RoleName.Client,
      },
      select: {
        id: true,
      },
    })
    if (!role) {
      throw new Error('Client role not found')
    }
    this.clientRoleId = role.id
    return this.clientRoleId
  }

  async getRoleById(id: number): Promise<Role | null> {
    if (this.rolesCache.has(id)) {
      return this.rolesCache.get(id)!
    }
    const role = await this.prismaService.role.findUnique({
      where: { id },
    })
    if (role) {
      this.rolesCache.set(id, role)
    }
    return role
  }
}
