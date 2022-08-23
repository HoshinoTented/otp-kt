import hoshino.otp.Algorithm
import hoshino.otp.totp.ConstantDateProvider
import hoshino.otp.totp.TOTPGenerator
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals

class TOTPTests {
    // Appendix B.  Test Vectors

    //   This section provides test values that can be used for the HOTP time-
    //   based variant algorithm interoperability test.
    //    The test token shared secret uses the ASCII string value
    //   "12345678901234567890".  With Time Step X = 30, and the Unix epoch as
    //   the initial value to count time steps, where T0 = 0, the TOTP
    //   algorithm will display the following values for specified modes and
    //   timestamps.
    //
    //  +-------------+--------------+------------------+----------+--------+
    //  |  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
    //  +-------------+--------------+------------------+----------+--------+
    //  |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
    //  |             |   00:00:59   |                  |          |        |
    //  |      59     |  1970-01-01  | 0000000000000001 | 46119246 | SHA256 |
    //  |             |   00:00:59   |                  |          |        |
    //  |      59     |  1970-01-01  | 0000000000000001 | 90693936 | SHA512 |
    //  |             |   00:00:59   |                  |          |        |
    //  |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
    //  |             |   01:58:29   |                  |          |        |
    //  |  1111111109 |  2005-03-18  | 00000000023523EC | 68084774 | SHA256 |
    //  |             |   01:58:29   |                  |          |        |
    //  |  1111111109 |  2005-03-18  | 00000000023523EC | 25091201 | SHA512 |
    //  |             |   01:58:29   |                  |          |        |
    //  |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
    //  |             |   01:58:31   |                  |          |        |
    //  |  1111111111 |  2005-03-18  | 00000000023523ED | 67062674 | SHA256 |
    //  |             |   01:58:31   |                  |          |        |
    //  |  1111111111 |  2005-03-18  | 00000000023523ED | 99943326 | SHA512 |
    //  |             |   01:58:31   |                  |          |        |
    //  |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
    //  |             |   23:31:30   |                  |          |        |
    //  |  1234567890 |  2009-02-13  | 000000000273EF07 | 91819424 | SHA256 |
    //  |             |   23:31:30   |                  |          |        |
    //  |  1234567890 |  2009-02-13  | 000000000273EF07 | 93441116 | SHA512 |
    //  |             |   23:31:30   |                  |          |        |
    //  |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
    //  |             |   03:33:20   |                  |          |        |
    //  |  2000000000 |  2033-05-18  | 0000000003F940AA | 90698825 | SHA256 |
    //  |             |   03:33:20   |                  |          |        |
    //  |  2000000000 |  2033-05-18  | 0000000003F940AA | 38618901 | SHA512 |
    //  |             |   03:33:20   |                  |          |        |
    //  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
    //  |             |   11:33:20   |                  |          |        |
    //  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 77737706 | SHA256 |
    //  |             |   11:33:20   |                  |          |        |
    //  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 47863826 | SHA512 |
    //  |             |   11:33:20   |                  |          |        |
    //  +-------------+--------------+------------------+----------+--------+
    @Test
    fun basicTest0() {
        data class TestData(val time: Long, val totpValue: Int, val crypto: Algorithm)

        val cyclic = sequence {
            while (true) yieldAll("1234567890".toList())
        }

        val expected = listOf(
            TestData(59, 94287082, Algorithm.HmacSHA1),
            TestData(59, 46119246, Algorithm.HmacSHA256),
            TestData(59, 90693936, Algorithm.HmacSHA512),
            TestData(1111111109,  7081804, Algorithm.HmacSHA1),
            TestData(1111111109, 68084774, Algorithm.HmacSHA256),
            TestData(1111111109, 25091201, Algorithm.HmacSHA512),
            TestData(1111111111, 14050471, Algorithm.HmacSHA1),
            TestData(1111111111, 67062674, Algorithm.HmacSHA256),
            TestData(1111111111, 99943326, Algorithm.HmacSHA512),
            TestData(1234567890, 89005924, Algorithm.HmacSHA1),
            TestData(1234567890, 91819424, Algorithm.HmacSHA256),
            TestData(1234567890, 93441116, Algorithm.HmacSHA512),
            TestData(2000000000, 69279037, Algorithm.HmacSHA1),
            TestData(2000000000, 90698825, Algorithm.HmacSHA256),
            TestData(2000000000, 38618901, Algorithm.HmacSHA512),
            TestData(20000000000, 65353130, Algorithm.HmacSHA1),
            TestData(20000000000, 77737706, Algorithm.HmacSHA256),
            TestData(20000000000, 47863826, Algorithm.HmacSHA512),
        )

        for (data in expected) {
            val secretKeyLength = when (data.crypto) {
                Algorithm.HmacSHA1 -> 20
                Algorithm.HmacSHA256 -> 32
                Algorithm.HmacSHA512 -> 64
            }

            // generate secretKey from "1234567890" cycle
            val secretKey = cyclic.take(secretKeyLength).toList().let { chars ->
                StringBuilder(secretKeyLength).apply {
                    chars.forEach { this.append(it) }
                }.toString().toByteArray()
            }

            val gen = TOTPGenerator(secretKey,
                digits = 8,
                crypto = data.crypto.name,
                timeStep = 30L, dateDecrease = 0L,
                dateProvider = ConstantDateProvider(Instant.ofEpochSecond(data.time)))

            val totp = gen.generate(true)

            assertEquals(data.totpValue, totp.value)
        }
    }
}