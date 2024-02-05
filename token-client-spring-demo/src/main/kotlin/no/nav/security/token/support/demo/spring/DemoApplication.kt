package no.nav.security.token.support.demo.spring

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class DemoApplication

fun main(args : Array<String>) {
    runApplication<DemoApplication>(*args) {
        setAdditionalProfiles("mock")
    }
}