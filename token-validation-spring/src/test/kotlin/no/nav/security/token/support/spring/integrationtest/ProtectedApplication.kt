package no.nav.security.token.support.spring.integrationtest

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class ProtectedApplication {
    fun main(args: Array<String>) {
        runApplication<ProtectedApplication>(*args)
    }
}