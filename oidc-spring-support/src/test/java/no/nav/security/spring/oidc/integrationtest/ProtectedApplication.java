package no.nav.security.spring.oidc.integrationtest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ProtectedApplication {
    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(ProtectedApplication.class);
        app.run(args);
    }
}
