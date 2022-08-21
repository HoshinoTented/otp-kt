package hoshino.otp.hotp

import hoshino.otp.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

typealias Counter = Long

/**
 * HMAC-Based One-Time Password
 *
 * 包含一个密码值和对应的 counter 值
 */
data class HOTP(
    override val value : Int,
    val counter: Counter) : OneTimePassword

/**
 * [HMAC-Based One-Time Password](https://www.rfc-editor.org/rfc/rfc4226) Generator
 *
 * Notice: NOT Thread-Safe
 *
 * @param secretKey 密钥
 * @param counter 计数器，会因为 [generate] 方法的调用而增长
 * @param digits 输出的密码长度，默认为 6
 * @param crypto 使用的 HMAC 算法，默认为 [Algorithm.HmacSHA1]
 */
class HOTPGenerator(
    val secretKey : SecretKey,
    var counter : Counter,
    val digits : Int = 6,
    val crypto : String = Algorithm.HmacSHA1.name) : OTPGenerator<HOTP> {

    override fun generate(checksum: Boolean) : HOTP {
        // Convert long value into byte array
        val counterBytes = ByteBuffer
            .allocate(8)
            .order(ByteOrder.BIG_ENDIAN)        // this is default value
            .putLong(counter)
            .array()

        val hash = hmac(crypto, secretKey, counterBytes)
        val truncated = dynamicTruncate(hash)

        val otp = HOTP(truncated.truncate(digits), counter)

        if (! checksum) counter += 1

        return otp
    }
}