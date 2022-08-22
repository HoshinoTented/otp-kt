@file:Suppress("UnnecessaryVariable")

package hoshino.otp.totp

import hoshino.otp.Algorithm
import hoshino.otp.OTPGenerator
import hoshino.otp.OneTimePassword
import hoshino.otp.SecretKey
import hoshino.otp.hotp.HOTPGenerator

data class TOTP(
    override val value: Int,
    val timeWindow: LongRange
) : OneTimePassword

/**
 * [Time-Based One-Time Password](https://www.rfc-editor.org/rfc/rfc6238.html) Generator
 *
 * Notice: NOT Thread-Safe
 *
 * @param secretKey 密钥
 * @param digits 生成的密码长度，默认为 6
 * @param crypto 使用的 HMAC 算法，默认为 [Algorithm.HmacSHA1]
 * @param timeStep X 变量，时间窗口的长度
 * @param dateDecrease T0 变量，时间的向前偏移值
 * @param dateProvider 提供所有 [TOTPGenerator] 所需要用到的时间，默认是 [SystemDateProvider]
 */
class TOTPGenerator(
    val secretKey: SecretKey,
    val digits: Int = 6,
    val crypto: String = Algorithm.HmacSHA1.name,
    val timeStep: Long = 30L,       // X
    val dateDecrease: Long = 0L,    // T0
    val dateProvider: DateProvider = SystemDateProvider
) : OTPGenerator<TOTP> {
    companion object {
        @JvmStatic
        fun timeFactor(timeStep: Long, dateDecrease: Long, dateProvider: DateProvider): Long {
            val unixSeconds = dateProvider.currentTime()
            val factor = (unixSeconds - dateDecrease) / timeStep

            return factor
        }

        @JvmStatic
        fun generateTOTP(secretKey: SecretKey, digits: Int, crypto: String, timeStep: Long, dateDecrease: Long, dateProvider: DateProvider): TOTP {
            val factor = timeFactor(timeStep, dateDecrease, dateProvider)
            val hotp = HOTPGenerator.generate(secretKey, factor, digits, crypto)

            val timeWindowBegin = factor * timeStep
            return TOTP(hotp.value, timeWindowBegin until (timeWindowBegin + timeStep))
        }
    }

    override fun generate(checksum: Boolean): TOTP {
        return generateTOTP(secretKey, digits, crypto, timeStep, dateDecrease, dateProvider)
    }
}