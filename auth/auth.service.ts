import { Injectable, UnauthorizedException, BadRequestException, InternalServerErrorException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import type { Response } from 'express'; // 🚩 ضروري جداً إضافة كلمة type هنا
import { authenticator } from '@otplib/preset-default'
import * as QRCode from 'qrcode'
import { randomUUID , randomBytes} from 'crypto'
import axios from 'axios'
import { RealtimeGateway } from '../realtime/realtime.gateway'
import { ConfigService } from '@nestjs/config'

authenticator.options = {

  step: 30,

  window: [0, 0]
}

  @Injectable()
  export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private realtime: RealtimeGateway,
    private readonly config: ConfigService
  ) {}

  /**
   * 🔐 كان هنا fallback نصي مكتوب في الكود:
   *    process.env.FLOW_SECRET || 'fallback_flow_secret_key_123'
   *
   * ده كان معناه إن أي بيئة ناقصها المتغير بتوقّع تدفق التسجيل بمفتاح
   * معروف. اتشال، و FLOW_SECRET بقى إجباري وقت الإقلاع
   * (شوف common/config/env.validation.ts).
   *
   * getter مش property: مهيّئات الخصائص بتشتغل قبل ما باراميترات
   * الـ constructor تتسند، فلو كانت property عادية كانت هتقرأ undefined.
   */
  private get FLOW_SECRET(): string {
    return this.config.getOrThrow<string>('security.flowSecret');
  }

 

  async createRegisterFlow(accountType: string) {
    const flow_id = crypto.randomBytes(16).toString('hex');
    const flow_signature = crypto
      .createHmac('sha256', this.FLOW_SECRET)
      .update(flow_id + accountType)
      .digest('hex');

    return { flow_id, flow_signature };
  }

  async processRegistration(
  data: any,
  token: string,
  signature: string,
  res: Response
) {

  const expectedSignature = crypto
    .createHmac('sha256', this.FLOW_SECRET)
    .update(token + data.accounttype)
    .digest('hex')

  if (signature !== expectedSignature) {
    throw new BadRequestException(
      'خطأ في أمان عملية التسجيل'
    )
  }

  const existingUser =
    await this.prisma.users.findFirst({

      where: {
        OR: [
          { email: data.email },
          { username: data.username }
        ]
      }
    })

  if (existingUser) {

    throw new BadRequestException(
      'البريد الإلكتروني أو اسم المستخدم مستخدم بالفعل'
    )
  }

  const hashedPassword =
    await bcrypt.hash(
      data.password,
      10
    )

  /**
   * ✅ otp
   */
  const otp =

    Math.floor(
      100000 +
      Math.random() * 900000
    ).toString()

  const otpExpires =
    new Date(
      Date.now() +
      1 * 60 * 1000
    )

  return this.prisma.$transaction(

    async (tx) => {

      /**
       * ✅ create user
       */
      const user =
        await tx.users.create({

          data: {

            email:
              data.email,

            username:
              data.username,

            password:
              hashedPassword,

            fullname:
              data.business_name ||
              data.username,

            accounttype:
              data.accounttype,

            country:
              data.country,

            email_otp:
              otp,

            email_otp_expires_at:
              otpExpires,

            email_otp_last_sent_at:
              new Date(),
          }
        })

      /**
       * ✅ session id
       */
      const sessionId =
        randomUUID()

      /**
       * ✅ trust device
       */
      if (data.hardware_fingerprint) {

        await tx.devices.create({

          data: {

            user_id:
              user.id,

            fingerprint:
              data.hardware_fingerprint,

            verified_at:
              new Date(),

            created_at:
              new Date(),

            updated_at:
              new Date(),

            last_active_at:
              new Date(),

            browser:
              data.user_agent || null,

            platform:

              data.user_agent?.includes(
                'Mobi'
              )

                ? 'Mobile'

                : 'Desktop',

            os:

              data.user_agent?.includes(
                'Windows'
              )

                ? 'Windows'

                : 'Other',

            session_id:
              sessionId
          }
        })
      }

      /**
       * ✅ save session
       */
      await tx.users.update({

        where: {
          id: user.id
        },

        data: {
          session_id:
            sessionId
        }
      })

      /**
       * ✅ send otp
       */
      await this.sendOtpEmail(
        user.email,
        otp
      )

      /**
       * ✅ payload
       */
      const payload = {

        sub:
          user.id.toString(),

        email:
          user.email,

        username:
          user.username,

        session_id:
          sessionId
      }

      /**
       * ✅ token
       */
      const access_token =
        await this.jwtService.signAsync(

          payload,

          {
            expiresIn: '30m'
          }
        )

      /**
       * ✅ VERY IMPORTANT
       * save auth cookie
       */
      res.cookie(

        'access_token',

        access_token,

        {

          httpOnly: true,

          secure:
            process.env.NODE_ENV ===
            'production',

          sameSite: 'lax',

          maxAge:
            1000 * 60 * 30,

          path: '/',
        }
      )

      /**
       * ✅ response
       */
      return {

        success: true,

        authenticated: true,

        session_id:
          sessionId,

        user: {

          id:
            user.id.toString(),

          email:
            user.email,

          username:
            user.username,

          two_factor_enabled:
            user.two_factor_enabled
        }
      }
    }
  )
}

  // src/auth/auth.service.ts
// src/auth/auth.service.ts

async login(
  email: string,
  pass: string,
  captchaToken: string | null,
  fingerprint: string,
  ua: string,
  ip: string,
  res: Response
) {
  // ✅ تأكد إن fingerprint valid
  const cleanFingerprint = fingerprint?.trim() || null

  /**
   * ✅ ip block
   */
  const ipBlock = await this.prisma.login_blocks.findFirst({
    where: {
      ip_address: ip,
      blocked_until: {
        gt: new Date()
      }
    }
  })

  if (ipBlock) {
    return {
      success: false,
      globally_blocked: true,
      message: `For security reasons, your account has been temporarily locked. You can attempt to log in again at ${ipBlock.blocked_until?.toLocaleTimeString([], {
        hour: 'numeric',
        minute: '2-digit'
      })}.`
    }
  }

  /**
   * ✅ fingerprint block (بس لو fingerprint موجود)
   */
  if (cleanFingerprint) {
    const block = await this.prisma.login_blocks.findUnique({
      where: {
        fingerprint: cleanFingerprint
      }
    })

    if (
      block?.blocked_until &&
      new Date() < block.blocked_until
    ) {
      return {
        success: false,
        globally_blocked: true,
        message: `For security reasons, your account has been temporarily locked. You can attempt to log in again at ${block?.blocked_until?.toLocaleTimeString([], {
          hour: 'numeric',
          minute: '2-digit'
        })}.`
      }
    }
  }

  const user = await this.prisma.users.findUnique({
    where: {
      email
    }
  })

  /**
   * ❌ account locked
   */
  if (
    user?.login_locked_until &&
    new Date() < user.login_locked_until
  ) {
    return {
      success: false,
      locked: true,
      message: `For security reasons, your account has been temporarily locked. You can attempt to log in again at ${user.login_locked_until.toLocaleTimeString([], {
        hour: 'numeric',
        minute: '2-digit'
      })}.`
    }
  }

  /**
   * ✅ captcha required
   */
  if (
    (user?.login_attempts || 0) >= 4
  ) {
    if (!captchaToken) {
      return {
        success: false,
        requires_captcha: true,
        message: 'يرجى التحقق من الكابتشا'
      }
    }
  }

  /**
   * ❌ user not found
   */
  if (!user) {
    if (cleanFingerprint) {
      await this.prisma.login_blocks.upsert({
        where: {
          fingerprint: cleanFingerprint
        },
        update: {
          attempts: {
            increment: 1
          },
          ip_address: ip
        },
        create: {
          fingerprint: cleanFingerprint,
          ip_address: ip,
          attempts: 1
        }
      })
    }

    return {
      success: false,
      message: 'Email or password is incorrect.'
    }
  }

  /**
   * ❌ invalid credentials
   */
  if (
    !(await bcrypt.compare(pass, user.password))
  ) {
    /**
     * ✅ attempts
     */
    const attempts = user.login_attempts || 0
    const nextAttempts = attempts + 1

    /**
     * ✅ global attempts (بس لو fingerprint موجود)
     */
    if (cleanFingerprint) {
      const globalBlock = await this.prisma.login_blocks.upsert({
        where: {
          fingerprint: cleanFingerprint
        },
        update: {
          attempts: {
            increment: 1
          }
        },
        create: {
          fingerprint: cleanFingerprint,
          ip_address: ip,
          attempts: 1
        }
      })

      if (globalBlock.attempts >= 6) {
        const blockedUntil = new Date(Date.now() + 30 * 60 * 1000)

        await this.prisma.login_blocks.update({
          where: {
            fingerprint: cleanFingerprint
          },
          data: {
            attempts: 0,
            blocked_until: blockedUntil
          }
        })

        return {
          success: false,
          globally_blocked: true,
          message: `For security reasons, your account has been temporarily locked. You can attempt to log in again at ${blockedUntil.toLocaleTimeString([], {
            hour: 'numeric',
            minute: '2-digit'
          })}.`
        }
      }
    }

    /**
     * ✅ remaining
     */
    const remaining = Math.max(0, 5 - nextAttempts)

    /**
     * ✅ lock account
     */
    if (nextAttempts >= 6) {
      const lockUntil = new Date(Date.now() + 15 * 60 * 1000)

      await this.prisma.users.update({
        where: {
          id: user.id
        },
        data: {
          login_attempts: 0,
          login_locked_until: lockUntil
        }
      })

      return {
        success: false,
        locked: true,
        message: `For security reasons, your account has been temporarily locked. You can attempt to log in again at ${lockUntil.toLocaleTimeString([], {
          hour: 'numeric',
          minute: '2-digit'
        })}.`
      }
    }

    /**
     * ✅ update attempts
     */
    await this.prisma.users.update({
      where: {
        id: user.id
      },
      data: {
        login_attempts: nextAttempts,
        last_login_attempt_at: new Date()
      }
    })

    /**
     * ✅ require captcha
     */
    const requiresCaptcha = nextAttempts >= 4

    /**
     * ✅ force captcha
     */
    if (requiresCaptcha && !captchaToken) {
      return {
        success: false,
        requires_captcha: true,
        message: 'يرجى إكمال التحقق الأمني'
      }
    }

    /**
     * ✅ final warning
     */
    if (remaining === 1) {
      return {
        success: false,
        requires_captcha: requiresCaptcha,
        remaining_tries: remaining,
        message: `Email or password is incorrect. You have 1 try left.\n\nIf you don't know your password, we recommend that you click the "Forgot your password" button to reset your password.`
      }
    }

    return {
      success: false,
      requires_captcha: requiresCaptcha,
      remaining_tries: remaining,
      message: `Email or password is incorrect. You have ${remaining} tries left.`
    }
  }

  // ريست لعدد المحاولات عند نجاح كلمة المرور
  await this.prisma.users.update({
    where: {
      id: user.id
    },
    data: {
      login_attempts: 0,
      login_locked_until: null,
      last_login_attempt_at: null
    }
  })

  /**
   * ✅ trusted device check
   */
  const trusted = await this.prisma.devices.findFirst({
    where: {
      user_id: user.id,
      fingerprint: cleanFingerprint || '',
      verified_at: {
        not: null
      }
    }
  })

  /**
   * ✅ trusted login route
   */
  if (trusted) {
    /**
     * ✅ restore session
     */
    await this.prisma.devices.update({
      where: {
        id: trusted.id
      },
      data: {
        logged_out_at: null,
        last_active_at: new Date(),
        updated_at: new Date()
      }
    })

    /**
     * ✅ 2FA check
     */
    if (user.two_factor_enabled) {
      return {
        success: true,
        requires_2fa: true,
        user: {
          id: user.id.toString(),
          email: user.email
        }
      }
    }

    /**
     * ✅ normal login for trusted device
     */
    return this.generateAuthResponse(
      user,
      cleanFingerprint || '',
      ua,
      res,
      ip
    )
  }

  /**
   * ⚠️ Device Not Trusted -> Trigger Verification Flow
   */
  const otp = Math.floor(100000 + Math.random() * 900000).toString()

  /**
   * ✅ check existing device record
   */
  const existingDevice = await this.prisma.devices.findFirst({
    where: {
      user_id: user.id,
      fingerprint: cleanFingerprint || ''
    }
  })

  if (existingDevice) {
    await this.prisma.devices.update({
      where: {
        id: existingDevice.id
      },
      data: {
        verification_token: otp,
        verification_expires_at: new Date(Date.now() + 10 * 60 * 1000),
        verified_at: null,
        browser: ua,
        updated_at: new Date(),
        last_active_at: new Date()
      }
    })
  } else {
    /**
     * ✅ create new device record
     */
    await this.prisma.devices.create({
      data: {
        user_id: user.id,
        fingerprint: cleanFingerprint || '',
        verification_token: otp,
        verification_expires_at: new Date(Date.now() + 10 * 60 * 1000),
        browser: ua,
        created_at: new Date(),
        updated_at: new Date(),
        last_active_at: new Date(),
        platform: ua.includes('Mobi') ? 'Mobile' : 'Desktop',
        os: ua.includes('Windows') ? 'Windows' : 'Other'
      }
    })
  }

  // ✅ send device verification otp
  try {
    await this.sendOtpEmail(user.email, otp)
  } catch (error) {
    console.log('SEND OTP ERROR:', error)
    return {
      success: false,
      message: 'فشل إرسال كود تفعيل الجهاز'
    }
  }

  return {
    requires_device_verification: true,
    user: {
      id: user.id.toString(),
      email: user.email
    }
  }
}

  async forgotPassword(
  email: string
) {

  const user =
    await this.prisma.users.findUnique({

      where: { email }
    })

  /**
   * ✅ silent response
   */
  if (!user) {

    return {

    success: false,

    exists: false,

    message:
      'Email does not exist'

    }
  }


  /**
   * ✅ secure random code
   */
  const rawCode =

    randomBytes(48)
      .toString('base64url')

  /**
   * ✅ expiration
   */
  const expiresAt =

    new Date(
      Date.now() +
      5 * 60 * 1000
    )

  await this.prisma.users.update({

    where: {
      id: user.id
    },

    data: {

      password_reset_code:
        rawCode,

      password_reset_expires_at:
        expiresAt
    }
  })

  const resetUrl =

`${process.env.FRONTEND_URL}/recover-password?code=${rawCode}`

  /**
   * ✅ send email
   */
  await this.sendRecoverPasswordEmail(

user.email,

resetUrl
)

  return {

    success: true
  }
}

async verifyRecoverCode(
  code: string
) {

  const user =
    await this.prisma.users.findFirst({

      where: {

        password_reset_code:
          code
      }
    })

  if (!user) {

    throw new BadRequestException(
      'Invalid code'
    )
  }

  if (

    !user.password_reset_expires_at ||

    user.password_reset_expires_at <
      new Date()
  ) {

    throw new BadRequestException(
      'Code expired'
    )
  }

  return {

    valid: true,
    used: false
  }
}

async resetPassword(
  body: any
) {

  const user =
    await this.prisma.users.findFirst({

      where: {

        password_reset_code:
          body.code
      }
    })

  if (!user) {

    throw new BadRequestException(
      'Invalid code'
    )
  }

  if (

    !user.password_reset_expires_at ||

    user.password_reset_expires_at <
      new Date()
  ) {

    throw new BadRequestException(
      'Code expired'
    )
  }

  const hashedPassword =

    await bcrypt.hash(
      body.password,
      12
    )

  await this.prisma.users.update({

    where: {
      id: user.id
    },

    data: {

      password:
        hashedPassword,

      /**
       * ✅ logout all devices
       */
      session_id:
        randomUUID(),

      password_reset_code:
        null,

      password_reset_expires_at:
        null
    }
  })
  await this.prisma.users.update({

  where: {
    id: user.id
  },

  data: {

    password_reset_code:
      null,

    password_reset_expires_at:
      null
  }
})

  return {

    success: true
  }
}

async verifyOtp(

  email: string,

  code: string,

  fingerprint: string,

  ua: string,

  res: Response
) {

  if (!code) {

    return {
      success: false,
      message:
        'أدخل كود التفعيل'
    }
  }

  const user =
  await this.prisma.users.findUnique({

    where: {
      email
    }
  })

if (!user) {

  return {

    success: false,

    message:
      'المستخدم غير موجود'
  }
}

if (

  user.email_otp !== code
) {

  return {

    success: false,

    message:
      'كود التفعيل غير صحيح'
  }
}

  // ✅ انتهت الصلاحية
  if (

    user.email_otp_expires_at &&

    new Date() >
      user.email_otp_expires_at
  ) {

    return {
      success: false,
      message:
        'انتهت صلاحية الكود'
    }
  }

  // ✅ تفعيل
  const updatedUser =
  await this.prisma.users.update({

    where: {
      id: user.id
    },

    data: {

      email_verified_at:
        new Date(),

      email_otp: null,

      email_otp_expires_at:
        null,

      email_otp_attempts: 0,

      email_otp_resend_attempts: 0,

      email_otp_blocked_until:
        null
    }
  })

const authResponse =
  await this.generateAuthResponse(
    updatedUser,
    fingerprint,
    ua,
    res
  )

  return authResponse
}

async resendOtp(
  email: string
) {

  const user =
    await this.prisma.users.findUnique({

      where: {
        email
      }
    })

  /**
   * ❌ user not found
   */
  if (!user) {

    return {

      success: false,

      message:
        'تعذر العثور على المستخدم'
    }
  }

  /**
   * ❌ already verified
   */
  if (user.email_verified_at) {

    return {

      success: false,

      message:
        'تم تفعيل البريد بالفعل'
    }
  }

  /**
   * ❌ blocked
   */
  if (

    user.email_otp_blocked_until &&

    new Date() <
      user.email_otp_blocked_until
  ) {

    const remainingMs =

      new Date(
        user.email_otp_blocked_until
      ).getTime() -

      Date.now()

    const remainingMinutes =

      Math.ceil(
        remainingMs / 1000 / 60
      )

    return {

      success: false,

      message:

        `تم حظر إعادة الإرسال مؤقتاً. حاول بعد ${remainingMinutes} دقيقة`
    }
  }

  /**
   * ❌ cooldown
   */
  if (

    user.email_otp_last_sent_at &&

    Date.now() -

      new Date(
        user.email_otp_last_sent_at
      ).getTime()

      < 60_000
  ) {

    const remainingSeconds =

      60 -

      Math.floor(

        (
          Date.now() -

          new Date(
            user.email_otp_last_sent_at
          ).getTime()

        ) / 1000
      )

    return {

      success: false,

      message:

        `انتظر ${remainingSeconds} ثانية قبل إعادة الإرسال`
    }
  }

  /**
   * ❌ resend attempts
   */
  const attempts =

    user.email_otp_resend_attempts || 0

  /**
   * ❌ block after 5 attempts
   */
  if (attempts >= 5) {

    const blockedUntil =

      new Date(
        Date.now() +
        60 * 60 * 1000
      )

    await this.prisma.users.update({

      where: {
        id: user.id
      },

      data: {

        email_otp_blocked_until:
          blockedUntil,

        email_otp_resend_attempts: 0
      }
    })

    return {

      success: false,

      message:
        'تم حظر إعادة الإرسال لمدة ساعة'
    }
  }

  /**
   * ✅ generate otp
   */
  const otp =

    Math.floor(
      100000 +
      Math.random() * 900000
    ).toString()

  const expiresAt =

    new Date(
      Date.now() +
      10 * 60 * 1000
    )

  /**
   * ✅ update user
   */
  await this.prisma.users.update({

    where: {
      id: user.id
    },

    data: {

      email_otp:
        otp,

      email_otp_expires_at:
        expiresAt,

      email_otp_last_sent_at:
        new Date(),

      email_otp_resend_attempts: {
        increment: 1
      }
    }
  })

  /**
   * ✅ send otp
   */
  await this.sendOtpEmail(
    user.email,
    otp
  )

  return {

    success: true,

    message:
      'تم إرسال كود جديد'
  }
}


private async sendOtpEmail(
  email: string,
  otp: string
) {

  console.log(`
    OTP for ${email}: ${otp}
  `)

}
private async sendRecoverPasswordEmail(

email: string,

resetUrl: string
) {

console.log(`

Recover password link for ${email}

${resetUrl}

`)
}


async verifyDeviceCode(
  code: string,
  fingerprint: string,
  ua: string,
  res: Response,
  ip: string
) {

  const device =
    await this.prisma.devices.findFirst({
      where: {
        verification_token: code,
        fingerprint
      },
      include: {
        users: true
      }
    })

  /**
   * ❌ invalid code
   */
  if (!device) {
    return {
      success: false,
      message: 'كود التحقق غير صحيح'
    }
  }

  /**
   * ❌ expired
   */
  if (
    device.verification_expires_at &&
    new Date() > device.verification_expires_at
  ) {
    return {
      success: false,
      message: 'انتهت صلاحية الكود'
    }
  }

  /**
   * ✅ verify device
   */
  await this.prisma.devices.update({
    where: {
      id: device.id
    },
    data: {
      verified_at: new Date(),
      verification_token: null,
      verification_expires_at: null,
      ip_address: ip,
      updated_at: new Date()
    }
  })

  // 🍏 ملحوظة أمنية: لو المستخدم مفعل الـ 2FA الثنائي، المنطقي إنه برضه يظهر بعد ما يفعل جهازه للتأكيد الصارم
  if (device.users.two_factor_enabled) {
    return {
      requires_2fa: true,
      user: {
        email: device.users.email
      }
    }
  }

  /**
   * 🍏 التعديل السحري: تفعيل الجهاز بنجاح وإرجاع الـ Flag للفرونت إند 
   * بدون تسجيل دخول مباشر وبدون توليد التوكنات في هذه المرحلة
   */
  return { 
    authenticated: true, 
    success: true, 
    message: 'تم تفعيل وتوثيق الجهاز بنجاح' 
  }
}

async resendDeviceOtp(
  email: string,
  fingerprint: string
) {

  const user =
    await this.prisma.users.findUnique({

      where: {
        email
      }
    })

  if (!user) {

    return {

      success: false,

      message:
        'المستخدم غير موجود'
    }
  }

  const device =
    await this.prisma.devices.findFirst({

      where: {

        user_id: user.id,

        fingerprint
      }
    })

  if (!device) {

    return {

      success: false,

      message:
        'الجهاز غير موجود'
    }
  }

  if (

  device.updated_at &&

  Date.now() -

    new Date(
      device.updated_at
    ).getTime()

    < 60_000
) {

  return {

    success: false,

    message:
      'انتظر 60 ثانية'
  }
}

  const otp =

    Math.floor(
      100000 +
      Math.random() * 900000
    ).toString()

  await this.prisma.devices.update({

  where: {
    id: device.id
  },

  data: {

    verification_token:
      otp,

    verification_expires_at:

      new Date(
        Date.now() +
        10 * 60 * 1000
      ),

    updated_at:
      new Date()
  }
})

  await this.sendOtpEmail(
    user.email,
    otp
  )

  return {

    success: true,

    message:
      'تم إرسال كود جديد'
  }
}

  async generateAuthResponse(
    user: any,
    fingerprint: string,
    ua: string,
    res: Response,
    ip?: string
  ) {
    /**
     * ❌ invalid user
     */
    if (!user || !user.id) {
      throw new UnauthorizedException('المستخدم غير صالح');
    }

    /**
     * ✅ current device
     */
    const device = await this.prisma.devices.findFirst({
      where: {
        user_id: user.id,
        fingerprint
      }
    });

    const sessionId = user.session_id || randomUUID();


await this.prisma.users.update({

  where: {
    id: user.id
  },

  data: {

    session_id:
      sessionId,

    last_activity_at:
      new Date()
  }
})
    /**
     * ✅ jwt payload
     */
    const payload = {
      sub: user.id.toString(),
      email: user.email,
      username: user.username,
      session_id: sessionId,
      device_id: device?.id || null,
    };

    /**
     * ✅ sign token
     */
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_SECRET,
      expiresIn: '7d'
    });

    /**
     * ✅ httpOnly cookie
     */
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
    });

    /**
     * 📢 [REALTIME EVENT] تحديث فوري للألوان والواجهة
     */
    if (device) {
      const userIdStr = user.id.toString();
      const deviceIdStr = device.id.toString();

      // إخطار كافة الشاشات المفتوحة للمستخدم بالدخول الفوري لتحديث ألوان الأجهزة
      this.realtime.server.to(`user:${userIdStr}`).emit('device_logged_in', {
        deviceId: deviceIdStr
      });
      this.realtime.server.to(`user:${userIdStr}`).emit('devices_updated');
    }

    /**
     * ✅ response
     */
   return {
  success: true,
  authenticated: true,
  session_id: sessionId,
  device_id: device?.id,
  user: {
    id: user.id.toString(),
    email: user.email,
    username: user.username,
    two_factor_enabled: user.two_factor_enabled
  }
}
  }

    async checkPendingDevice(
  fingerprint: string
) {

  if (!fingerprint) {

    return {
      requires_verification: false
    }
  }

  try {

    const pending =
      await this.prisma.devices.findFirst({

        where: {

          fingerprint,

          verified_at: null,

          verification_token: {
            not: null
          }
        },

        include: {
          users: true
        }
      })

    /**
     * ❌ no pending
     */
    if (!pending) {

      return {

        requires_verification:
          false
      }
    }

    /**
     * ❌ expired
     */
    if (

      pending.verification_expires_at &&

      new Date() >
        pending.verification_expires_at
    ) {

      await this.prisma.devices.update({

        where: {
          id: pending.id
        },

        data: {

          verification_token:
            null,

          verification_expires_at:
            null
        }
      })

      return {

        requires_verification:
          false
      }
    }

    /**
     * ✅ still pending
     */
    return {

      requires_verification:
        true,

      email:
        pending.users.email
    }

  } catch (error) {

    console.error(
      'Pending device error:',
      error
    )

    return {

      requires_verification:
        false
    }
  }
}

async generate2FA(
  userId: bigint
) {

  const user =
    await this.prisma.users.findUnique({

      where: {
        id: userId
      }
    })

  if (!user) {

    return {

      success: false,

      message:
        'المستخدم غير موجود'
    }
  }

  /**
   * ✅ generate secret
   */
  const secret =
    authenticator.generateSecret()

  /**
   * ✅ otpauth url
   */
  const otpauth =
    authenticator.keyuri(

      user.email,

      'MyApp',

      secret
    )

  /**
   * ✅ save secret
   */
  await this.prisma.users.update({

    where: {
      id: user.id
    },

    data: {

      two_factor_secret:
        secret,

      two_factor_enabled:
        false
    }
  })

  /**
   * ✅ qr code
   */
  const qrCode =
    await QRCode.toDataURL(
      otpauth
    )

  return {

    success: true,

    qrCode,

    secret
  }
}
async confirm2FA(
  userId: bigint,
  code: string,
  fingerprint: string,
  ua: string,
  res: Response,
  ip: string
) {

  try {

    /**
     * ✅ validate
     */
    if (
      !code ||
      typeof code !== 'string'
    ) {

      return {
        success: false,
        message: 'كود غير صالح'
      }
    }

    const cleanCode =
      code.trim()

    if (
      cleanCode.length !== 6
    ) {

      return {
        success: false,
        message:
          'أدخل الكود بالكامل'
      }
    }

    /**
     * ✅ user
     */
    const user =
      await this.prisma.users.findUnique({

        where: {
          id: BigInt(userId)
        }
      })

    if (
      !user ||
      !user.two_factor_secret
    ) {

      return {
        success: false,
        message:
          '2FA غير متاح'
      }
    }

    /**
     * ✅ verify
     */
    const verified =
      authenticator.verify({

        token: cleanCode,

        secret:
          user.two_factor_secret
      })

    /**
     * ❌ invalid
     */
    if (!verified) {

      return {
        success: false,
        message:
          'الكود غير صحيح'
      }
    }

    /**
     * ✅ NEW SESSION
     */
    const newSessionId =
      randomUUID()

    /**
     * ✅ update user
     */
    const updatedUser =
      await this.prisma.users.update({

        where: {
          id: user.id
        },

        data: {

          two_factor_enabled:
            true,

          two_factor_confirmed_at:
            new Date(),

          /**
           * ✅ IMPORTANT
           */
          session_id:
            newSessionId
        }
      })

    /**
     * ✅ update device
     */
    await this.prisma.devices.updateMany({

      where: {
        user_id: user.id,
        fingerprint
      },

      data: {

        session_id:
          newSessionId,

        verified_at:
          new Date(),

        logged_out_at:
          null,

        last_active_at:
          new Date(),

        updated_at:
          new Date()
      }
    })

    /**
     * ✅ payload
     */
    const payload = {

      sub:
        updatedUser.id.toString(),

      email:
        updatedUser.email,

      username:
        updatedUser.username,

      session_id:
        newSessionId
    }

    /**
     * ✅ fresh token
     */
    const accessToken =
      await this.jwtService.signAsync(

        payload,

        {
          secret:
            process.env.JWT_SECRET,

          expiresIn: '7d'
        }
      )

    /**
     * ✅ overwrite cookie
     */
    res.cookie(

      'access_token',

      accessToken,

      {

        httpOnly: true,

        secure:
          process.env.NODE_ENV ===
          'production',

        sameSite: 'lax',

        path: '/',

        maxAge:
          1000 *
          60 *
          60 *
          24 *
          7
      }
    )

    /**
     * ✅ response
     */
    return {

      success: true,

      authenticated: true,

      session_id:
        newSessionId,

      user: {

        id:
          updatedUser.id.toString(),

        email:
          updatedUser.email,

        username:
          updatedUser.username,

        two_factor_enabled:
          true
      }
    }

  } catch (error) {

    console.log(
      'CONFIRM 2FA ERROR:',
      error
    )

    return {

      success: false,

      message:
        'Internal server error'
    }
  }
}

async disable2FA(

  userId: bigint,

  code: string
) {

  /**
   * ✅ find user
   */
  const user =
    await this.prisma.users.findUnique({

      where: {
        id: userId
      }
    })

  /**
   * ❌ unavailable
   */
  if (
    !user ||
    !user.two_factor_enabled ||
    !user.two_factor_secret
  ) {

    return {

      success: false,

      message:
        'المصادقة الثنائية غير مفعلة'
    }
  }

  /**
   * ❌ invalid code
   */
  if (

    !code ||

    code.length !== 6
  ) {

    return {

      success: false,

      message:
        'أدخل كود صحيح'
    }
  }

  /**
   * ✅ verify
   */
  let verified = false

  try {

    verified =
      authenticator.verify({

        token: code,

        secret:
          user.two_factor_secret
      })

  } catch {

    return {

      success: false,

      message:
        'تعذر التحقق من الكود'
    }
  }

  /**
   * ❌ invalid
   */
  if (!verified) {

    return {

      success: false,

      message:
        'الكود غير صحيح'
    }
  }

  /**
   * ✅ disable
   */
  await this.prisma.users.update({

    where: {
      id: user.id
    },

    data: {

      two_factor_enabled:
        false,

      two_factor_secret:
        null,

      two_factor_confirmed_at:
        null
    }
  })

  return {

    success: true,

    message:
      'تم تعطيل المصادقة الثنائية'
  }
}

async get2FAStatus(
  userId: bigint
) {

  const user =
    await this.prisma.users.findUnique({

      where: {
        id: userId
      }
    })

  if (!user) {

    return {

      two_factor_enabled:
        false,

      email_verified:
        false
    }
  }

  return {

    two_factor_enabled:
      user.two_factor_enabled,

    email_verified:
      !!user.email_verified_at
  }
}

async verify2FALogin(

  email: string,

  code: string,

  fingerprint: string,

  ua: string,

  res: Response,

  ip: string
) {

  /**
   * ✅ find user
   */
  const user =
    await this.prisma.users.findUnique({

      where: {
        email
      }
    })

  /**
   * ❌ user not found
   */
  if (!user) {

    return {

      success: false,

      message:
        'المستخدم غير موجود'
    }
  }

  /**
   * ❌ 2FA not enabled
   */
  if (

    !user.two_factor_enabled ||

    !user.two_factor_secret ||

    typeof user.two_factor_secret !==
      'string'
  ) {

    return {

      success: false,

      message:
        'المصادقة الثنائية غير مفعلة'
    }
  }

  /**
   * ❌ invalid code format
   */
  if (

    !code ||

    code.length !== 6
  ) {

    return {

      success: false,

      message:
        'أدخل كود صحيح'
    }
  }

  /**
   * ✅ verify
   */
  let verified = false

  try {

    verified =
      authenticator.verify({

        token: code,

        secret:
          user.two_factor_secret
      })

  } catch (error) {

    console.log(
      '2FA VERIFY ERROR:',
      error
    )

    return {

      success: false,

      message:
        'تعذر التحقق من الكود'
    }
  }

  /**
   * ❌ invalid
   */
  if (!verified) {

    return {

      success: false,

      message:
        'الكود غير صحيح'
    }
  }

  /**
   * ✅ success
   */
  return this.generateAuthResponse(

    user,

    fingerprint,

    ua,

    res,

    ip
  )
}
  // أضف هذه الدالة داخل AuthService إذا كانت ناقصة
  async findUserById(id: string) {
    const user = await this.prisma.users.findUnique({
      where: { id: BigInt(id) },
      select: {
        id: true,
        fullname: true,
        email: true,
        username: true,
        email_verified_at: true,
        accounttype: true,
        last_activity_at: true
      },

   
    });
    if (!user) return null;
    return { ...user, id: user.id.toString() };
  }
  // --- 4. Availability Checks ---
  async isEmailAvailable(email: string) {
    const user = await this.prisma.users.findUnique({ where: { email } });
    return { available: !user };
  }

  async isUsernameAvailable(username: string) {
    const user = await this.prisma.users.findUnique({ where: { username } });
    return { available: !user };
  }

// async logout(
//   userId: bigint,
//   fingerprint: string,
//   res: Response
// ) {

//   const device =
//     await this.prisma.devices.findFirst({

//       where: {
//         user_id: userId,
//         fingerprint
//       }
//     })

//   if (device) {

//     await this.prisma.devices.update({

//       where: {
//         id: device.id
//       },

//       data: {

//         logged_out_at:
//           new Date(),

//         updated_at:
//           new Date(),

//         session_id:
//           null
//       }
//     })

//     this.realtime.notifyDeviceLogout(

//       userId.toString(),

//       device.id.toString()
//     )
//   }

//   /**
//    * ✅ clear cookies
//    */
//   res.clearCookie(

//     'access_token',

//     {

//       httpOnly: true,

//       secure:
//         process.env.NODE_ENV ===
//         'production',

//       sameSite: 'lax',

//       path: '/',
//     }
//   )

//   return {
//     success: true
//   }
// }

   async refreshTokens(currentToken: string, ua: string, ip: string, res: Response) {
    try {
      // فك التوكن الحالي مع التغاضي عن انتهاء وقت الصلاحية لإنقاذه وتمديده
      const payload = await this.jwtService.verifyAsync(currentToken, {
        secret: process.env.JWT_SECRET,
        ignoreExpiration: true, // 💡 حاسمة جداً لنجاح التجديد التلقائي
      });

      // التحقق من هوية المستخدم في قاعدة البيانات (PostgreSQL)
      const user = await this.prisma.users.findUnique({
        where: { id: BigInt(payload.sub) }
      });
      
      if (!user || user.session_id !== payload.session_id) {
        throw new UnauthorizedException('Session revoked or user invalid');
      }

      // توليد الـ Payload الجديد والمطابق تماماً لنظامك
      const newPayload = {
        sub: user.id.toString(),
        email: user.email,
        username: user.username,
        session_id: user.session_id,
        device_id: payload.device_id || null,
      };

      // إصدار توكن رسمي ممدد وصالح لـ 7 أيام إضافية
      const newAccessToken = await this.jwtService.signAsync(newPayload, {
        secret: process.env.JWT_SECRET,
        expiresIn: '7d',
      });

      // إعادة تعيين الكوكي الأمنية بالتوكن الجديد
      res.cookie('access_token', newAccessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 أيام
      });

      return {
        success: true,
        authenticated: true,
        session_id: user.session_id,
        message: 'Session silent refresh completed successfully',
      };

    } catch (error) {
      throw new UnauthorizedException('Invalid session token');
    }
  }

  async logout(userId: bigint, fingerprint: string, res: Response) {
  const device = await this.prisma.devices.findFirst({
    where: { user_id: userId, fingerprint }
  })

  if (device) {
    await this.prisma.devices.update({
      where: { id: device.id },
      data: {
        logged_out_at: new Date(),
        updated_at: new Date(),
        session_id: null,
        // ✅ ضيف ده — يمنع الجهاز من الدخول تاني
        verified_at: null,
        verification_token: null,
      }
    })
    this.realtime.notifyDeviceLogout(userId.toString(), device.id.toString())
  }

  res.clearCookie('access_token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  })

  res.cookie('access_token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    expires: new Date(0),
  })

  return { success: true }
}

}
