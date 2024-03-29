package no.nav.security.token.support.client.spring.oauth2

import java.lang.annotation.Inherited
import org.springframework.context.annotation.Import
import kotlin.annotation.AnnotationTarget.ANNOTATION_CLASS
import kotlin.annotation.AnnotationTarget.CLASS

/**
 * Enables OAuth 2.0 clients for retrieving accesstokens using the
 * *client_credentials* and *on-behalf-of* flows.
 */
@MustBeDocumented
@Inherited
@Retention(AnnotationRetention.RUNTIME)
@Target(ANNOTATION_CLASS, CLASS)
@Import(OAuth2ClientConfiguration::class)
annotation class EnableOAuth2Client(
        /**
         * Enable caching for OAuth 2.0 access_token response in the [OAuth2AccessTokenService]
         * @return default value false, true if enabled
         */
        val cacheEnabled: Boolean = false,
        /**
         * Set the maximum cache size
         * @return the maximum entries in each cache instance
         */
        val cacheMaximumSize: Long = 1000,
        /**
         * Set skew time in seconds for cache eviction, i.e. the amount of time a cache entry
         * should be evicted before the actual "expires_in" in [OAuth2AccessTokenResponse]
         * @return the skew in seconds
         */
        val cacheEvictSkew: Long = 10)