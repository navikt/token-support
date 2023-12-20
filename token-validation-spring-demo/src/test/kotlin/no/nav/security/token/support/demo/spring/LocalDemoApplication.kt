package no.nav.security.token.support.demo.spring

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication

@SpringBootApplication
class LocalDemoApplication {

    fun main(args : Array<String>) {
        val app = SpringApplication(LocalDemoApplication::class.java)
        app.setAdditionalProfiles("local")
        app.run(*args)
    }
}