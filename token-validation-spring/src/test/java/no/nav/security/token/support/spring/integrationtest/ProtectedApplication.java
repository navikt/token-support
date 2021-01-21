package no.nav.security.token.support.spring.integrationtest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ProtectedApplication {
    public static void main(String[] args) {
        new SpringApplication(ProtectedApplication.class).run(args);
    }
}
