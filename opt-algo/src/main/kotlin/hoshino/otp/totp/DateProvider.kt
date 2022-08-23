package hoshino.otp.totp

import java.time.Instant

interface DateProvider {
    /**
     * 返回一个 “当前时间”，单位是秒
     */
    fun currentTime(): Long
}

object SystemDateProvider : DateProvider {
    override fun currentTime(): Long {
        return Instant.now().epochSecond
    }
}

data class ConstantDateProvider(val instant: Instant) : DateProvider {
    override fun currentTime(): Long {
        return instant.epochSecond
    }
}