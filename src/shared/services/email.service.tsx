import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Resend } from 'resend'
import * as React from 'react'
import { OTPEmail } from 'emails/otp'

@Injectable()
export class EmailService {
  private resend: Resend
  private from: string

  constructor(private readonly configService: ConfigService) {
    this.resend = new Resend(this.configService.get<string>('resend.apiKey'))
    this.from = this.configService.get<string>('app.emailFrom')!
  }
  async sendOTP(payload: { email: string; code: string }) {
    const subject = 'Mã OTP'
    return this.resend.emails.send({
      from: this.from,
      to: [payload.email],
      subject,
      react: <OTPEmail otpCode={payload.code} title={subject} />,
    })
  }
}
