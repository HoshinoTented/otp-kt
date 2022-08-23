plugins {
    kotlin("jvm") version "1.7.10" apply false
}

allprojects {
    apply(plugin = "kotlin")

    repositories {
        maven("https://maven.aliyun.com/repository/public")
        mavenCentral()
    }
}