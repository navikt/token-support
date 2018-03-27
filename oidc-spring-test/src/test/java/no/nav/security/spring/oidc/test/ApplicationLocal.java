package no.nav.security.spring.oidc.test;

import static org.springframework.boot.SpringApplication.run;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import(TokenGeneratorConfiguration.class)
public class ApplicationLocal {
    public static void main(String[] args) {
        run(ApplicationLocal.class, args);
    }
}
