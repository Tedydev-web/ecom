import { Injectable } from '@nestjs/common'
import { Device, Session } from '@prisma/client'
import { DeviceType, RegisterBodyType, RoleType, VerificationCodeType } from 'src/routes/auth/auth.model'
import { TypeOfVerificationCodeType } from 'src/shared/constants/auth.constant'
import { UserType } from 'src/shared/models/shared-user.model'
import { PrismaService } from 'src/shared/services/prisma.service'

export type UpsertDeviceData = Pick<Device, 'userId' | 'lastIp'> &
  Partial<Pick<Device, 'fingerprint' | 'name' | 'type' | 'os' | 'browser'>>

export type CreateSessionData = Pick<Session, 'userId' | 'deviceId' | 'ipAddress' | 'userAgent' | 'expiresAt'>

@Injectable()
export class AuthRepository {
  constructor(private readonly prismaService: PrismaService) {}

  async createUser(
    user: Pick<UserType, 'email' | 'name' | 'password' | 'phoneNumber' | 'roleId'>,
  ): Promise<Omit<UserType, 'password' | 'totpSecret'>> {
    return this.prismaService.user.create({
      data: user,
      omit: {
        password: true,
        totpSecret: true,
      },
    })
  }

  async createUserInclueRole(
    user: Pick<UserType, 'email' | 'name' | 'password' | 'phoneNumber' | 'avatar' | 'roleId'>,
  ): Promise<UserType & { role: RoleType }> {
    return this.prismaService.user.create({
      data: user,
      include: {
        role: true,
      },
    })
  }

  async createVerificationCode(
    payload: Pick<VerificationCodeType, 'email' | 'type' | 'code' | 'expiresAt'>,
  ): Promise<VerificationCodeType> {
    return this.prismaService.verificationCode.upsert({
      where: {
        email_code_type: {
          email: payload.email,
          code: payload.code,
          type: payload.type,
        },
      },
      create: payload,
      update: {
        code: payload.code,
        expiresAt: payload.expiresAt,
      },
    })
  }

  async findUniqueVerificationCode(
    uniqueValue:
      | { id: number }
      | {
          email_code_type: {
            email: string
            code: string
            type: TypeOfVerificationCodeType
          }
        },
  ): Promise<VerificationCodeType | null> {
    return this.prismaService.verificationCode.findUnique({
      where: uniqueValue,
    })
  }

  async upsertDevice(data: UpsertDeviceData): Promise<Device> {
    const now = new Date()
    const deviceData = {
      userId: data.userId,
      fingerprint: data.fingerprint,
      name: data.name,
      type: data.type,
      os: data.os,
      browser: data.browser,
      lastIp: data.lastIp,
      lastActiveAt: now,
    }

    if (data.fingerprint) {
      return this.prismaService.device.upsert({
        where: { fingerprint: data.fingerprint },
        create: deviceData,
        update: {
          lastIp: data.lastIp,
          lastActiveAt: now,
        },
      })
    }

    return this.prismaService.device.create({ data: deviceData })
  }

  async createSession(data: CreateSessionData): Promise<Session> {
    return this.prismaService.session.create({ data })
  }

  async findValidSessionById(id: string): Promise<(Session & { user: UserType & { role: RoleType } }) | null> {
    return this.prismaService.session.findFirst({
      where: {
        id,
        revokedAt: null,
        expiresAt: {
          gt: new Date(),
        },
      },
      include: {
        user: {
          include: {
            role: true,
          },
        },
      },
    })
  }

  async updateSessionLastActive(id: string): Promise<Session> {
    return this.prismaService.session.update({
      where: { id },
      data: { lastActiveAt: new Date() },
    })
  }

  async revokeSession(id: string): Promise<Session> {
    return this.prismaService.session.update({
      where: { id },
      data: { revokedAt: new Date() },
    })
  }

  async findUniqueUserIncludeRole(uniqueObject: { email: string } | { id: number }) {
    return this.prismaService.user.findUnique({
      where: uniqueObject,
      include: {
        role: true,
        _count: {
          select: {
            sessions: { where: { revokedAt: null, expiresAt: { gte: new Date() } } },
            devices: true,
          },
        },
      },
    })
  }

  updateUser(where: { id: number } | { email: string }, data: Partial<Omit<UserType, 'id'>>): Promise<UserType> {
    return this.prismaService.user.update({
      where,
      data,
    })
  }

  deleteVerificationCode(
    uniqueValue:
      | { id: number }
      | {
          email_code_type: {
            email: string
            code: string
            type: TypeOfVerificationCodeType
          }
        },
  ): Promise<VerificationCodeType> {
    return this.prismaService.verificationCode.delete({
      where: uniqueValue,
    })
  }
}
