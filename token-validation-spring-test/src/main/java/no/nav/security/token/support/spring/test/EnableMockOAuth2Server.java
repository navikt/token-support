package no.nav.security.token.support.spring.test;

import org.springframework.boot.test.autoconfigure.properties.PropertyMapping;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Import({
    MockOAuth2ServerAutoConfiguration.class,
    MockLoginController.class
})
@PropertyMapping(MockOAuth2ServerProperties.PREFIX)
public @interface EnableMockOAuth2Server {
    /**
     * Specify port for server to run on (only works in test scope), provide via
     * env property mock-ouath2-server.port outside of test scope
     */
    int port() default 0;
}
