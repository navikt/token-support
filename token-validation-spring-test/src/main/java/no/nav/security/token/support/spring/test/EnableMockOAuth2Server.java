package no.nav.security.token.support.spring.test;

import org.springframework.boot.test.autoconfigure.properties.PropertyMapping;
import org.springframework.context.annotation.Import;
import java.lang.annotation.*;

@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Import({
    MockOAuth2ServerConfiguration.class,
    MockOAuth2ServerAutoConfiguration.class
})
@PropertyMapping(MockOAuth2ServerProperties.PREFIX)
public @interface EnableMockOAuth2Server {
    int port() default 0;
}
