package no.nav.security.token.support.demo.spring

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication

@SpringBootApplication
class DemoApplication {

    fun main(args : Array<String>) {
        val app = SpringApplication(DemoApplication::class.java)
        app.run(*args)
    }
}