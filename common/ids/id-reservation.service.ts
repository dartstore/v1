import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from '../../prisma/prisma.service'

/**
 * ══════════════════════════════════════════════════════════════════
 * حجز المعرّفات قبل الإدراج
 * ══════════════════════════════════════════════════════════════════
 *
 * ليه موجودة أصلاً:
 *
 * صيغة الـ AAD المجمّدة (common/crypto) بتربط كل نص مشفّر بـ
 * (المتجر، الوضع، نوع الصف، **معرّف الصف**، اسم الحقل). يعني المعرّف
 * لازم يكون معروف **قبل** التشفير، مش بعد الإدراج.
 *
 * البديل — إدراج الصف الأول وبعدين تشفير وتحديث — معناه إن الصف
 * بيتولد ثانية بقيمة غير مشفّرة أو فاضية، وإن كل كتابة بتبقى عمليتين.
 * ده اللي رفضناه.
 *
 * الآلية:
 *
 *   nextval(pg_get_serial_sequence('table','id'))
 *
 * خصائص مهمة:
 *   • ذرّية — استدعاءين متوازيين مستحيل يرجّعوا نفس الرقم.
 *   • **مش تفاعلية مع الـ transaction** — الـ sequence بتتقدّم حتى لو
 *     الـ transaction اترجعت. وده المطلوب بالظبط: معرّف اتربط بيه نص
 *     مشفّر ماينفعش يترجع للاستخدام تاني.
 *   • بتسيب فجوات في الأرقام. الفجوات دي طبيعية ومتوقعة ومش مشكلة.
 *
 * ⚠️ قيد على المرحلة 1b: أي جدول هيخزّن نص مشفّر مربوط بـ AAD لازم
 * يكون مفتاحه BigInt مربوط بـ sequence. ممنوع UUID أو معرّف بيتولد
 * في التطبيق للجداول دي.
 */

/** الجداول المسموح الحجز منها — قائمة صريحة بدل اسم جدول حر */
export interface ReservableTable {
  /** اسم الجدول في قاعدة البيانات (اللي في @@map) */
  readonly table: string
  /** عمود المفتاح الأساسي */
  readonly column: string
}

/**
 * فاضية في المرحلة 1a: مفيش جدول بيخزّن نص مشفّر لسه.
 * المرحلة 1b هتضيف payment_accounts وأخواته.
 */
export const RESERVABLE_TABLES: Readonly<Record<string, ReservableTable>> = {}

export class IdReservationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'IdReservationError'
    Object.setPrototypeOf(this, IdReservationError.prototype)
  }
}

/** أقصى عدد معرّفات في الحجز الواحد — حاجز أمان ضد استدعاء بالغلط */
const MAX_BATCH = 1000

@Injectable()
export class IdReservationService {
  private readonly logger = new Logger(IdReservationService.name)

  constructor(private readonly prisma: PrismaService) {}

  /**
   * يحجز معرّف واحد.
   *
   * بيتنفّذ خارج أي transaction عن قصد — حتى لو المستدعي جوه واحدة،
   * nextval مالهاش علاقة بالـ transaction، والمعرّف المحجوز مش هيترجع.
   */
  async reserve(key: string): Promise<bigint> {
    const [id] = await this.reserveMany(key, 1)
    return id
  }

  /**
   * يحجز مجموعة معرّفات متتالية.
   *
   * مفيدة للإدراج بالجملة: بنجيب كل المعرّفات مرة واحدة، بنشفّر، وبعدين
   * createMany في عملية واحدة.
   */
  async reserveMany(key: string, count: number): Promise<bigint[]> {
    const target = this.resolve(key)

    if (!Number.isSafeInteger(count) || count < 1) {
      throw new IdReservationError(
        `عدد المعرّفات لازم يكون عدد صحيح موجب (استلمنا: ${count}).`,
      )
    }

    if (count > MAX_BATCH) {
      throw new IdReservationError(
        `الحد الأقصى للحجز الواحد ${MAX_BATCH} معرّف (طُلب: ${count}).`,
      )
    }

    // القيم متمرّرة كباراميترات مش مدمجة في النص، فمفيش أي احتمال حقن.
    // pg_get_serial_sequence بتاخد أسماء نصية، فالباراميترات شغالة معاها.
    const rows = await this.prisma.$queryRaw<{ id: bigint }[]>`
      SELECT nextval(pg_get_serial_sequence(${target.table}, ${target.column})) AS id
      FROM generate_series(1, ${count})
    `

    if (rows.length !== count) {
      throw new IdReservationError(
        `توقعنا ${count} معرّف من ${target.table} واستلمنا ${rows.length}.`,
      )
    }

    return rows.map((row) => {
      const value = row.id
      if (typeof value !== 'bigint') {
        // بعض إعدادات الدرايفر بترجّع string لأنواع bigint
        return BigInt(value as unknown as string)
      }
      return value
    })
  }

  /** يتأكد إن الجدول مسجّل في القائمة المسموحة */
  private resolve(key: string): ReservableTable {
    const target = RESERVABLE_TABLES[key]

    if (!target) {
      const available = Object.keys(RESERVABLE_TABLES)
      throw new IdReservationError(
        `الجدول "${key}" مش مسجّل في RESERVABLE_TABLES. ` +
          (available.length > 0
            ? `المتاح: [${available.join(', ')}].`
            : `القائمة فاضية حالياً — أول جدول هيتضاف في المرحلة 1b.`),
      )
    }

    return target
  }
}
