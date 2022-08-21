package hoshino.otp

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and
import kotlin.math.pow

/// region Base HOTP

/**
 * [Dynamic Truncation](https://www.rfc-editor.org/rfc/rfc4226#section-5.3)
 */
fun dynamicTruncate(string : ByteArray) : Int {
    assert(string.size >= 20)

    val offset = (string.last() and 0xF).toInt()
    val result = ((string[offset] and 0x7F).toInt() shl 24) or
                      ((string[offset + 1].toUByte().toInt()) shl 16) or
                      (string[offset + 2].toUByte().toInt() shl 8) or
                      (string[offset + 3].toUByte().toInt())

    return result
}

/**
 * HMAC Algorithm
 *
 * @param crypto algorithm
 * @param key secretKey
 * @param text input message
 *
 * @see Algorithm
 */
fun hmac(crypto : String, key : ByteArray, text : ByteArray) : ByteArray {
    val hmac = Mac.getInstance(crypto)
    val secretKey = SecretKeySpec(key, "RAW")

    hmac.init(secretKey)
    return hmac.doFinal(text)
}

/// endregion

/// region Number

// pre-defined power of 10
private val DIGITS : IntArray = intArrayOf(1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000)

fun Int.truncate(digits: Int): Int {
    assert(digits > 0)

    val b = if (digits in 1..8) DIGITS[digits] else 10.0.pow(digits).toInt()

    return this.rem(b)
}

/// endregion