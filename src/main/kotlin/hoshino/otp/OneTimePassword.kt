package hoshino.otp

/**
 * OTP 接口，所有 [OTPGenerator.generate] 的返回值都应该是这个接口的子类。
 * 这使得能够包含除了主要密码外的一些信息，例如对于 TOTP 算法生成的密码还带有有效期。
 */
interface OneTimePassword {
    /**
     * 密码值
     */
    val value : Int
}