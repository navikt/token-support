package no.nav.security.token.support.oauth2.client;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import org.checkerframework.checker.index.qual.NonNegative;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
public class OAuth2ClientConfiguration {

    //TODO make cache opt-in and configurable
    @Bean
    OAuth2AccessTokenService oAuth2AccessTokenService(RestTemplateBuilder restTemplateBuilder,
                                                      TokenValidationContextHolder contextHolder) {
        OAuth2AccessTokenService oAuth2AccessTokenService =  new OAuth2AccessTokenService(contextHolder,
            new OnBehalfOfTokenResponseClient(restTemplateBuilder.build()),
            new ClientCredentialsTokenResponseClient(restTemplateBuilder.build()));
        oAuth2AccessTokenService.setClientCredentialsGrantCache(clientCredentialsCache());
        oAuth2AccessTokenService.setOnBehalfOfGrantCache(onBehalfOfCache());
        return oAuth2AccessTokenService;
    }

    //TODO: make bean opt-in
    @Bean
    Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse> onBehalfOfCache(){
        // Evict based on a varying expiration policy
        return Caffeine.newBuilder()
            .expireAfter(expiryOnResponseExpiresIn(OnBehalfOfGrantRequest.class))
            .build();
    }
    //TODO: make bean opt-in
    @Bean
    Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse> clientCredentialsCache(){
        // Evict based on a varying expiration policy
        return Caffeine.newBuilder()
            .expireAfter(expiryOnResponseExpiresIn(ClientCredentialsGrantRequest.class))
            .build();
    }

    private <T> Expiry<T, OAuth2AccessTokenResponse> expiryOnResponseExpiresIn(Class<T> clazz){
       return new Expiry<T, OAuth2AccessTokenResponse>() {
           @Override
           public long expireAfterCreate(@NonNull T key, @NonNull OAuth2AccessTokenResponse response, long currentTime) {
               long seconds = response.getExpiresIn();
               return TimeUnit.SECONDS.toNanos(seconds);
           }
           @Override
           public long expireAfterUpdate(@NonNull T key, @NonNull OAuth2AccessTokenResponse response,
                                         long currentTime, long currentDuration) {
               return currentDuration;
           }
           @Override
           public long expireAfterRead(@NonNull T key, @NonNull OAuth2AccessTokenResponse response,
                                       long currentTime, long currentDuration) {
               return currentDuration;
           }
       };
    }
}
