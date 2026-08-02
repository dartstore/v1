import { Injectable, NestMiddleware } from '@nestjs/common'
import { randomUUID } from 'crypto'
import type { NextFunction, Request, Response } from 'express'
import { TenantContextService } from './tenant-context.service'

/**
 * بيفتح سياق المستأجر لكل طلب.
 *
 * ⚠️ الميدلوير ده **مابيرفضش أي طلب ومابيوقفش أي حاجة**. بيفتح السياق
 * وبيكمّل. أي منطق تفويض بيفضل في الـ Guards الموجودة زي ما هو.
 *
 * الوضع الافتراضي live: المرحلة 1a مافيهاش حل للوضع، وأي كتابة على
 * جداول 1a بتاخد الوضع كمعامل صريح من المستدعي. الافتراضي هنا للتبليغ بس.
 */
@Injectable()
export class TenantContextMiddleware implements NestMiddleware {
  constructor(private readonly tenantContext: TenantContextService) {}

  use(request: Request, response: Response, next: NextFunction): void {
    const requestId =
      (request.headers['x-request-id'] as string | undefined) ?? randomUUID()

    response.setHeader('x-request-id', requestId)

    this.tenantContext.run(
      {
        storeId: null, // بيتملّى في الـ Guard في المرحلة 1b
        mode: 'live',
        actor: null,
        requestId,
      },
      () => next(),
    )
  }
}
