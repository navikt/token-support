package no.nav.security.token.support.test.spring;

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
