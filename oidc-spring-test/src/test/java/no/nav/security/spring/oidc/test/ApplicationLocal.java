package no.nav.security.spring.oidc.test;




import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;

import static org.springframework.boot.SpringApplication.run;

//@ComponentScan({"no.nav.security", "no.nav.foreldrepenger"})
@SpringBootApplication
@Import(TokenGeneratorConfiguration.class)
public class ApplicationLocal {
    public static void main(String[] args) {
        run(ApplicationLocal.class, args);
    }
}
