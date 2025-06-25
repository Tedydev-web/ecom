import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { authenticator } from 'otplib'

@Injectable()
export class TwoFactorService {
  constructor(private readonly configService: ConfigService) {}

  /**
   * Generates a TOTP secret and the corresponding URI for QR code generation.
   * @param email The user's email, used as the account name in the URI.
   * @returns An object containing the base32 secret and the key URI.
   */
  generateTOTPSecret(email: string) {
    const secret = authenticator.generateSecret()
    const appName = this.configService.get<string>('app.name')!
    const uri = authenticator.keyuri(email, appName, secret)
    return {
      secret,
      uri,
    }
  }

  /**
   * Verifies a TOTP token against a secret.
   * @param token The token from the user's authenticator app.
   * @param secret The secret stored for the user.
   * @returns A boolean indicating if the token is valid.
   */
  verifyTOTP({ token, secret }: { token: string; secret: string }): boolean {
    return authenticator.verify({
      token,
      secret,
    })
  }
}
