package no.nav.security.token.support.spring.test

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Configuration

@Configuration
@EnableAutoConfiguration
class TestApplication {

    fun main(args : Array<String>) {
        runApplication<TestApplication>(*args)
    }
}