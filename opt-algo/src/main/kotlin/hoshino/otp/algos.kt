package hoshino.otp

/**
 * 可能使用到的 Hmac 算法列表，为了提供静态检查
 */
@Suppress("SpellCheckingInspection")
enum class Algorithm {
    HmacSHA1,
    HmacSHA256,
    HmacSHA512
}