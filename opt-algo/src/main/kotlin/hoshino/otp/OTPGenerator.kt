package hoshino.otp

import hoshino.otp.hotp.HOTPGenerator

interface OTPGenerator<out T : OneTimePassword> {
    /**
     * 一个 One-Time Password
     *
     * @param checksum 是否为校验而生成，对于 [HOTPGenerator] 而言，执行后不会修改 [HOTPGenerator.counter]
     */
    fun generate(checksum: Boolean) : T
}