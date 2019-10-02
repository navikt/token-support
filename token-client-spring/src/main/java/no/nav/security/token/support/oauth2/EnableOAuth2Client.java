package no.nav.security.token.support.oauth2;

import no.nav.security.token.support.oauth2.client.OAuth2ClientConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Import({
    OAuth2ClientConfiguration.class,
    ClientConfigurationProperties.class
})
public @interface EnableOAuth2Client {
}
