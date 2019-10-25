package no.nav.security.token.support.client.spring.oauth2;

import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse;
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService;
import no.nav.security.token.support.client.spring.ClientConfigurationProperties;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * Enables OAuth 2.0 clients for retrieving accesstokens using the
 * <em>client_credentials</em> and <em>on-behalf-of</em> flows.
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Import({
    OAuth2ClientConfiguration.class,
    ClientConfigurationProperties.class
})
public @interface EnableOAuth2Client {
    /**
     * Enable caching for OAuth 2.0 access_token response in the
     * {@link OAuth2AccessTokenService}
     * @return default value false, true if enabled
     */
    boolean cacheEnabled() default false;

    /**
     * Set the maximum cache size
     *
     * @return the maximum entries in each cache instance
     */
    long cacheMaximumSize() default 1000;

    /**
     * Set skew time in seconds for cache eviction, i.e. the amount of time a cache entry
     * should be evicted before the actual "expires_in" in {@link OAuth2AccessTokenResponse}
     *
     * @return the skew in seconds
     */
    long cacheEvictSkew() default 10;
}
