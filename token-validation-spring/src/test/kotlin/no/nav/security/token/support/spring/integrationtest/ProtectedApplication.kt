package no.nav.security.token.support.spring.integrationtest

import org.springframework.boot.autoconfigure.SpringBootApplication
import kotlin.jvm.JvmStatic
import org.springframework.boot.SpringApplication

@SpringBootApplication
class ProtectedApplication {
    fun main(args: Array<String>) {
        SpringApplication(ProtectedApplication::class.java).run(*args)
    }
}