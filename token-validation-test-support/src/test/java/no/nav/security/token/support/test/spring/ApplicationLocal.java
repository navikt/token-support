package no.nav.security.token.support.test.spring;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

import static org.springframework.boot.SpringApplication.run;

@SpringBootApplication
@Import(TokenGeneratorConfiguration.class)
public class ApplicationLocal {
    public static void main(String[] args) {
        run(ApplicationLocal.class, args);
    }
}
