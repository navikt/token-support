package no.nav.security.token.support.oauth2.client;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.oauth2.EnableOAuth2Client;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotationMetadata;

import java.util.concurrent.TimeUnit;

@Configuration
public class OAuth2ClientConfiguration implements ImportAware {

    private AnnotationAttributes enableOAuth2ClientAttributes;

    @Override
    public void setImportMetadata(AnnotationMetadata enableOAuth2ClientMetadata) {
        this.enableOAuth2ClientAttributes = AnnotationAttributes.fromMap(
            enableOAuth2ClientMetadata.getAnnotationAttributes(EnableOAuth2Client.class.getName(), false));
        if (this.enableOAuth2ClientAttributes == null) {
            throw new IllegalArgumentException(
                "@EnableOAuth2Client is not present on importing class " + enableOAuth2ClientMetadata.getClassName());
        }
    }

    @Bean
    OAuth2AccessTokenService oAuth2AccessTokenService(RestTemplateBuilder restTemplateBuilder,
                                                      TokenValidationContextHolder contextHolder) {
        OAuth2AccessTokenService oAuth2AccessTokenService = new OAuth2AccessTokenService(
            contextHolder,
            new OnBehalfOfTokenClient(restTemplateBuilder.build()),
            new ClientCredentialsTokenClient(restTemplateBuilder.build()));

        if (enableOAuth2ClientAttributes != null && enableOAuth2ClientAttributes.getBoolean("cacheEnabled")) {
            long maximumSize = enableOAuth2ClientAttributes.getNumber("cacheMaximumSize");
            long skewInSeconds = enableOAuth2ClientAttributes.getNumber("cacheEvictSkew");
            oAuth2AccessTokenService.setClientCredentialsGrantCache(cache(maximumSize, skewInSeconds));
            oAuth2AccessTokenService.setOnBehalfOfGrantCache(cache(maximumSize, skewInSeconds));
        }
        return oAuth2AccessTokenService;
    }

    <T> Cache<T, OAuth2AccessTokenResponse> cache(long maximumSize, long skewInSeconds) {
        // Evict based on a varying expiration policy
        return Caffeine.newBuilder()
            .maximumSize(maximumSize)
            .expireAfter(evictOnResponseExpiresIn(skewInSeconds))
            .build();
    }

    private <T> Expiry<T, OAuth2AccessTokenResponse> evictOnResponseExpiresIn(long skewInSeconds) {
        return new Expiry<>() {
            @Override
            public long expireAfterCreate(@NonNull T key, @NonNull OAuth2AccessTokenResponse response,
                                          long currentTime) {
                long seconds = response.getExpiresIn() > skewInSeconds ?
                    response.getExpiresIn() - skewInSeconds : response.getExpiresIn();
                return TimeUnit.SECONDS.toNanos(seconds);
            }

            @Override
            public long expireAfterUpdate(@NonNull T key, @NonNull OAuth2AccessTokenResponse response,
                                          long currentTime, long currentDuration) {
                return currentDuration;
            }

            @Override
            public long expireAfterRead(@NonNull T key, @NonNull OAuth2AccessTokenResponse response, long currentTime
                , long currentDuration) {
                return currentDuration;
            }
        };
    }
}
