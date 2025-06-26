import { Inject, Injectable } from '@nestjs/common'
import { DeviceType, RoleType, SessionType, VerificationCodeType } from 'src/routes/auth/auth.model'
import { TypeOfVerificationCodeType } from 'src/shared/constants/auth.constant'
import * as tokens from 'src/shared/constants/injection.tokens'
import { UserType } from 'src/shared/models/shared-user.model'
import { PrismaService } from 'src/shared/services/prisma.service'

export type UpsertDeviceData = Pick<DeviceType, 'userId' | 'lastIp'> &
  Partial<Pick<DeviceType, 'fingerprint' | 'name' | 'type' | 'os' | 'browser'>>

export type CreateSessionData = Pick<SessionType, 'userId' | 'deviceId' | 'ipAddress' | 'userAgent' | 'expiresAt'>
export type ValidSessionWithUser = SessionType & { user: UserType & { role: RoleType } }

@Injectable()
export class AuthRepository {
  constructor(@Inject(tokens.PRISMA_SERVICE) private readonly prismaService: PrismaService) {}

  async createVerificationCode(
    payload: Pick<VerificationCodeType, 'email' | 'type' | 'code' | 'expiresAt'>,
  ): Promise<VerificationCodeType> {
    return await this.prismaService.verificationCode.create({
      data: payload,
    })
  }

  async findUniqueVerificationCode(uniqueValue: {
    email: string
    code: string
    type: TypeOfVerificationCodeType
  }): Promise<VerificationCodeType | null> {
    return await this.prismaService.verificationCode.findUnique({
      where: {
        email_code_type: uniqueValue,
      },
    })
  }

  async deleteVerificationCode(uniqueValue: {
    email: string
    code: string
    type: TypeOfVerificationCodeType
  }): Promise<VerificationCodeType> {
    return await this.prismaService.verificationCode.delete({
      where: {
        email_code_type: uniqueValue,
      },
    })
  }

  async upsertDevice(data: UpsertDeviceData): Promise<DeviceType> {
    const { userId, lastIp, fingerprint, ...deviceInfo } = data

    // 1. Cố gắng tìm thiết bị hiện có dựa trên fingerprint (nếu có) hoặc một tổ hợp các đặc điểm khác
    let existingDevice: DeviceType | null = null

    if (fingerprint) {
      existingDevice = (await this.prismaService.device.findUnique({
        where: { fingerprint },
      })) as DeviceType | null
    }

    if (!existingDevice) {
      existingDevice = (await this.prismaService.device.findFirst({
        where: {
          userId,
          name: deviceInfo.name || 'Unknown',
          type: deviceInfo.type || 'Unknown',
          os: deviceInfo.os || 'Unknown',
          browser: deviceInfo.browser || 'Unknown',
        },
      })) as DeviceType | null
    }

    // 2. Nếu tìm thấy, cập nhật nó. Nếu không, tạo một cái mới.
    if (existingDevice) {
      return (await this.prismaService.device.update({
        where: { id: existingDevice.id },
        data: {
          lastIp,
          lastActiveAt: new Date(),
        },
      })) as DeviceType
    } else {
      return (await this.prismaService.device.create({
        data: {
          userId,
          lastIp,
          fingerprint,
          name: deviceInfo.name || 'Unknown',
          type: deviceInfo.type || 'Unknown',
          os: deviceInfo.os || 'Unknown',
          browser: deviceInfo.browser || 'Unknown',
        },
      })) as DeviceType
    }
  }

  async createSession(data: CreateSessionData): Promise<SessionType> {
    return await this.prismaService.session.create({ data })
  }

  async findValidSessionById(id: string): Promise<ValidSessionWithUser | null> {
    const session = await this.prismaService.session.findFirst({
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
    return session as ValidSessionWithUser | null
  }

  async updateSessionLastActive(id: string): Promise<SessionType> {
    return await this.prismaService.session.update({
      where: { id },
      data: { lastActiveAt: new Date() },
    })
  }

  async revokeSession(id: string): Promise<SessionType> {
    return await this.prismaService.session.update({
      where: { id },
      data: { revokedAt: new Date() },
    })
  }
}
