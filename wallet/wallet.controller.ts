// src/wallet/wallet.controller.ts

/**
 * ⚠️ LEGACY — مقفول أمام أي استخدام جديد.
 * ══════════════════════════════════════════════════════════════════
 *
 * الملف ده متروك زي ما هو عن قصد وماتغيّرش سلوكه.
 *
 * الكود هنا بيخالف معايير التعامل مع الفلوس المتبعة في المشروع
 * (شوف docs/MONEY.md و AI_RULES.md):
 *
 *   • parseFloat على مبلغ مالي — الأرقام العشرية العائمة ماينفعش
 *     تستخدم مع الفلوس أبداً.
 *   • updateMany مع increment على رصيد مباشرةً — الأرصدة المفروض
 *     تكون محسوبة من قيود غير قابلة للتعديل، مش عمود بيتزوّد ويتنقص.
 *   • مفيش قيد محاسبي، ولا idempotency، ولا تحقق من المبلغ، ولا
 *     transaction.
 *
 * الملف ده هو الاستثناء الوحيد المسموح به من القاعدة دي، وهو استثناء
 * مؤقت. الخطة إنه يتعاد تصميمه فوق الـ Ledger في مرحلة لاحقة.
 *
 * ❌ ماتضيفش أي كود جديد هنا.
 * ❌ ماتستخدمش الملف ده كنموذج لأي كود بيتعامل مع فلوس.
 * ❌ ماتربطش أي منطق دفع بالكود ده.
 *
 * أي تعامل جديد مع الفلوس بيمشي على معماريّة الدفع الجديدة
 * (شوف docs/PAYMENTS-ARCHITECTURE.md).
 * ══════════════════════════════════════════════════════════════════
 */

import { Controller, Get, Post, Body, UseGuards, Req } from '@nestjs/common';
import { AuthGuard } from '../auth/auth.guard'; // تأكد من المسار
import { PrismaService } from '../prisma/prisma.service';

@Controller('wallet')
@UseGuards(AuthGuard)
export class WalletController {
  constructor(private readonly prisma: PrismaService) {}

  // src/wallet/wallet.controller.ts

@Get('super-fast-balance') // 👈 هذا هو المسار الفرعي
  async getBalance(@Req() req) {
    const userId = req.user.sub;
    
    const wallet = await this.prisma.wallets.findFirst({
      where: { user_id: BigInt(userId) }
    });

    return {
      balance: wallet?.balance?.toString() || "0.00",
      currency: wallet?.currency || "USDDC" // حسب السكيما عندك
    };
  }

@Post('top-up')
async topUp(@Body('amount') amount: string, @Req() req) {
  const userId = BigInt(req.user.sub);
  
  // نستخدم updateMany لأن user_id ليس الـ Primary Key
  // أو استخدم update لو أضفت @unique لحقل user_id في السكيما
  await this.prisma.wallets.updateMany({
    where: { user_id: userId },
    data: { 
      balance: { increment: parseFloat(amount) } 
    }
  });

  return { success: true };
}

 
}
