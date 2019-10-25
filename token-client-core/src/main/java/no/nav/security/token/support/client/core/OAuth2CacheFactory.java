package no.nav.security.token.support.client.core;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.concurrent.TimeUnit;

public class OAuth2CacheFactory {

    public static <T> Cache<T, OAuth2AccessTokenResponse> accessTokenResponseCache(long maximumSize, long skewInSeconds) {
        // Evict based on a varying expiration policy
        return Caffeine.newBuilder()
            .maximumSize(maximumSize)
            .expireAfter(evictOnResponseExpiresIn(skewInSeconds))
            .build();
    }

    private static  <T> Expiry<T, OAuth2AccessTokenResponse> evictOnResponseExpiresIn(long skewInSeconds) {
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
